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
#include <yuzu/server/auth_db.hpp>
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
#include "kek_op_lock.hpp"
#include "kek_rotate_control.hpp"
#include "kek_routes.hpp"
#include "key_provider.hpp"
#include "scim_routes.hpp"
#include "x509_ca.hpp"
#include "compliance_eval.hpp"
#include "custom_properties_store.hpp"
#include "data_export.hpp"
#include "deployment_store.hpp"
#include "discover_routes.hpp" // A2 discovery surface: /api/v1/discover/* (roadmap Issue 17.1)
#include "discovery_store.hpp"
#include "engine_principal_store.hpp"
#include "execution_event_bus.hpp"
#include "execution_tracker.hpp"
#include "gateway.grpc.pb.h"
#include "grpc_on_behalf_interceptor.hpp"
#include "guardian_journal_fleet_tags.hpp" // Guardian journal fleet gauge names + HELP (#2298)
#include "instruction_store.hpp"
#include "instruction_yaml.hpp"
#include "on_behalf_guard.hpp"
#include "principal_class.hpp"
#include "principal_quota_gate.hpp"
#include "rest_a4_envelope_http.hpp"
#include "inventory_store.hpp"
#include "app_perf_daily_store.hpp"
#include "app_perf_fleet_store.hpp"
#include "app_perf_cohort_reader.hpp"
#include "app_perf_group_reader.hpp"
#include "app_perf_rollup.hpp"
#include "dex_app_perf_model.hpp"
#include "offline_endpoint_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "device_inventory_store.hpp"
#include "software_inventory_store.hpp"
#include "software_licensing_store.hpp"
#include "product_registry_store.hpp"
#include "sle_routes.hpp"
#include "agent_decommission.hpp"
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
#include "saml_provider.hpp"
#include "quarantine_store.hpp"
#include "result_set_matcher.hpp"
#include "result_set_store.hpp"
#include "result_sets_ui.hpp"
#include "scope_yaml.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "dispatch_target_shape.hpp" // check_targeting_shape / targeting_supplied (#2500)
#include "authz_model.hpp" // #1788: per-arm visibility intersection (in_scope/filter_to_scope)
#include "dispatch_confined_arms.hpp" // the ONE per-arm intersection, shared with /api/command
#include "dispatch_scope_ladder.hpp" // A-3/QE-2: the shared scope-resolution ladder + caller wiring
#include "mcp_input_bounds.hpp" // kExecInstrBoundReasons — the boot pre-seed iterates it (#2437)
#include "mcp_jsonrpc.hpp"
#include "auth_routes.hpp"
#include "compliance_routes.hpp"
#include "guardian_routes.hpp"
#include "dex_alert_router.hpp"
#include "dex_blast_radius.hpp"
#include "guardian_ingest.hpp" // kGuardianEventStoreDurationMetric + warm_create_guardian_event_store_metric
#include "dex_perf_rules.hpp"
#include "dex_routes.hpp"
#include "network_perf_rules.hpp"
#include "inventory_routes.hpp"
#include "inventory_ci_join.hpp"
#include "network_routes.hpp"
#include "software_catalog_rollup.hpp"
#include "device_routes.hpp"
#include "preflight_eval.hpp"
#include "deployment_routes.hpp"
#include "deployment_run_store.hpp"
#include "preflight_routes.hpp"
#include "verify_routes.hpp"
#include "preflight_run_store.hpp"
#include "vuln_finding_store.hpp"
#include "access_review_store.hpp" // Periodic Access Reviews (SOC 2 CC6.2) — campaign persistence
#include "preflight_runner.hpp"
#include "tar_tree_routes.hpp"
#include "policy_evaluator.hpp"
#include "schedule_routes.hpp"
#include "schedule_runner.hpp"
#include "dashboard_routes.hpp"
#include "discovery_routes.hpp"
#include "fleet_topology_store.hpp"
#include "heartbeat_ingestion.hpp"
#include "fleet_topology_types.hpp"
#include "mcp_server.hpp"
#include "mcp_stream_bridge.hpp" // progress bridge core (2f PR 3a)
#include "stream_budget.hpp" // shared held-open-SSE admission budget (2f PR 2, Decision 15(h))
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
#include <expected>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
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

std::string trim_ascii_whitespace(std::string_view s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string_view::npos) return {};
    auto e = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(b, e - b + 1));
}
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

// -- Per-principal quota chokepoint helpers (PR 4.4) --------------------------
//
// The GATE DECISION (principal_kind/auth_source == "engine" check, mcp-vs-
// rest render pick, incl. is_streaming_path) and the thread_local slot
// itself (`tls_quota_slot()`) now live in principal_quota_gate.hpp — the
// latter moved there (UP-1) so streaming routes in other translation units
// (rest_api_v1.cpp, workflow_routes.cpp) can adopt the pending slot into
// their own stream lifetime via `adopt_quota_slot_into_stream`. server.cpp
// keeps only the httplib-specific, worker-thread-affine call sites below.

// -- KEK rotation seam helpers (#2395) -----------------------------------------
//
// The three KekOps lambdas (register_routes call site below) all need to
// serialize on a CLUSTER-WIDE session advisory lock before touching
// `auth_secret_codec_` — a rotate racing another rotate (on this server or
// another one pointed at the same database) must be refused, never
// interleaved. This is a DIFFERENT key from the codec's own INTERNAL
// transaction-scoped lock (`pg_advisory_xact_lock(2037545589,
// hashtext('secrets_kek'))`, pg/secret_codec.cpp:30, taken inside
// rotate_kek() itself) — reusing that key here would have our own call to
// rotate_kek() deadlock against the very lock we are holding. Same first
// argument (an arbitrary fixed classifier picked to match the codec's), but
// hashtext() of a distinct second-key string ('secrets_kek_op' vs
// 'secrets_kek'), which Postgres's two-key advisory-lock form keys on
// jointly — so the two locks never collide.


} // namespace detail

// -- ServerImpl ---------------------------------------------------------------

class ServerImpl final : public Server {
public:
    explicit ServerImpl(Config cfg, auth::AuthManager& auth_mgr)
        : cfg_(std::move(cfg)), auth_mgr_(auth_mgr), auto_approve_(), metrics_(), event_bus_(),
          registry_(event_bus_, metrics_),
          agent_service_(registry_, event_bus_, cfg_.tls_enabled && !cfg_.tls_ca_cert.empty(),
                         auth_mgr, auto_approve_, metrics_, cfg_.gateway_mode),
          api_rate_limiter_(cfg_.rate_limit), login_rate_limiter_(cfg_.login_rate_limit),
          principal_quota_(PrincipalQuotaConfig{.max_concurrency = cfg_.principal_max_concurrency,
                                                 .rate_per_second = cfg_.principal_rate_limit,
                                                 .burst = 2.0 * cfg_.principal_rate_limit}) {
        // Register metric descriptions
        metrics_.describe("yuzu_agents_connected", "Number of currently connected agents", "gauge");
        metrics_.describe("yuzu_nvd_total_cves", "Distinct CVEs in the local NVD catalog", "gauge");
        metrics_.describe("yuzu_nvd_backfill_complete",
                          "1 when the newest-first NVD backfill has reached its floor, else 0",
                          "gauge");
        metrics_.describe("yuzu_nvd_sync_failures_total",
                          "NVD sync window failures by reason (connection/http_429/http_403/"
                          "http_other/parse)",
                          "counter");
        // Initialise every reason series to 0 so the counter (and its HELP/TYPE)
        // is present in /metrics on a healthy server — otherwise absent()-style
        // alerts misfire and Grafana shows "No data" until the first failure (sre).
        for (auto r : kNvdCountedReasons) {
            metrics_.counter("yuzu_nvd_sync_failures_total", {{"reason", nvd_reason_label(r)}});
        }
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
        metrics_.describe("yuzu_http_requests_total",
                          "Total HTTP requests by method, status, and principal_class",
                          "counter");
        // Pre-seed the closed principal_class dimension (docs/observability-
        // conventions.md — every value of a closed-set label is initialised at
        // startup, matching yuzu_onbehalf_rejected_total below). method/status
        // are NOT closed sets, so a single representative GET/200 point per
        // class is the seed — not a cross-product, which would be unbounded.
        // "engine" is now included (PR 4.5 — principal_class_resolved makes it
        // live, emitted for a resolved engine-principal session): the closed
        // set is human/agent/none/engine and every value gets its 0-point.
        for (auto pc : {"human", "agent", "none", "engine"}) {
            metrics_.counter("yuzu_http_requests_total",
                             {{"method", "GET"}, {"status", "200"}, {"principal_class", pc}});
        }
        // ADR-1005 Interim rules (execution-plan PR 1.1): rejected on-behalf-of
        // assertions, by ingress surface. Pre-seeded to 0 per
        // docs/observability-conventions.md so absent() alerts stay meaningful.
        metrics_.describe("yuzu_onbehalf_rejected_total",
                          "Requests rejected for carrying a reserved on-behalf-of "
                          "header/metadata key (ADR-1005) by surface",
                          "counter");
        metrics_.counter("yuzu_onbehalf_rejected_total",
                         {{"surface", "http"}, {"event", "security"}});
        metrics_.counter("yuzu_onbehalf_rejected_total",
                         {{"surface", "grpc"}, {"event", "security"}});
        // Per-principal quota cap exhaustions (PR 4.4, ADR-1005 class engine
        // principals). Pre-seed all 4 closed series to 0 (docs/observability-
        // conventions.md), mirroring yuzu_onbehalf_rejected_total above.
        // Bounded labels only: side (engine/operator) x limit
        // (concurrency/rate) — never principal_id. This is operational, not
        // security (contrast the security event= on yuzu_onbehalf_rejected_
        // total above) — a quota cap is expected steady-state behaviour, not
        // an attack signal. side="operator" is dormant until Phase 5
        // (delegation debits the operator side); it is pre-seeded anyway,
        // deliberately, because it is a real documented QuotaSide dimension
        // (same reasoning as the principal_class="engine" pre-seed above,
        // which is now a live enum value as of PR 4.5).
        metrics_.describe("yuzu_server_principal_quota_exhausted_total",
                          "Per-principal quota-cap exhaustions by side and limit dimension",
                          "counter");
        for (auto side : {"engine", "operator"}) {
            for (auto limit : {"concurrency", "rate"}) {
                metrics_.counter("yuzu_server_principal_quota_exhausted_total",
                                 {{"side", side}, {"limit", limit}});
            }
        }
        // Admits companion (sre, governance hardening round): every
        // ADMITTED engine request, so exhaustion RATE (exhausted /
        // (exhausted + admits)) is computable — a self-brick immediately
        // after a --principal-* config change (rate near 1.0) is
        // distinguishable from ordinary load-driven exhaustion, which
        // yuzu_server_principal_quota_exhausted_total alone can't tell
        // apart. Bounded label set (side only — never principal_id),
        // pre-seeded beside the exhausted counter above for the same
        // absent()-alert reason.
        metrics_.describe("yuzu_server_principal_quota_admits_total",
                          "Per-principal quota-cap admits (successful try_acquire) by side",
                          "counter");
        for (auto side : {"engine", "operator"}) {
            metrics_.counter("yuzu_server_principal_quota_admits_total", {{"side", side}});
        }
        // Periodic Access Reviews (SOC 2 CC6.2) feature metrics — sre SHOULD
        // (governance): the feature previously carried zero metrics. Bounded
        // labels only (format and decision are both closed 2-value sets),
        // pre-seeded per docs/observability-conventions.md so absent()
        // alerts stay meaningful. Wired at the REST handlers in
        // rest_api_v1.cpp — the MCP twins (export_access_review,
        // open_access_review, record_attestation) are not double-counted
        // here.
        metrics_.describe("yuzu_access_review_export_total",
                          "Access review evidence exports (GET /api/v1/access-reviews/export), "
                          "by format",
                          "counter");
        for (auto format : {"json", "csv"}) {
            metrics_.counter("yuzu_access_review_export_total", {{"format", format}});
        }
        metrics_.describe("yuzu_access_review_export_duration_seconds",
                          "Latency of the cross-principal grant-population read "
                          "(build_access_review) behind GET /api/v1/access-reviews/export",
                          "histogram");
        metrics_.histogram("yuzu_access_review_export_duration_seconds");
        metrics_.describe("yuzu_access_review_campaigns_opened_total",
                          "Access review campaigns opened (POST /api/v1/access-reviews)",
                          "counter");
        metrics_.counter("yuzu_access_review_campaigns_opened_total");
        metrics_.describe("yuzu_access_review_attestations_total",
                          "Access review reviewer decisions recorded (POST "
                          "/api/v1/access-reviews/{id}/attestations), by decision",
                          "counter");
        for (auto decision : {"attested", "flagged_revoke"}) {
            metrics_.counter("yuzu_access_review_attestations_total", {{"decision", decision}});
        }
        // MCP Streamable HTTP transport (ADR-1005 Decision 15(k) — the family was
        // NAMED in the decision, not left to implementer discretion, so alerts can
        // be authored against it before every rung has landed). Pre-seeded to 0 per
        // docs/observability-conventions.md so absent() alerts stay meaningful, and
        // `reason` is a CLOSED set — every value is seeded here and no label value
        // is ever derived from caller-controlled input.
        metrics_.describe("yuzu_mcp_sessions_active", "MCP Streamable HTTP sessions currently live",
                          "gauge");
        metrics_.describe("yuzu_mcp_sessions_opened_total",
                          "MCP Streamable HTTP sessions minted on initialize", "counter");
        metrics_.describe("yuzu_mcp_streams_active",
                          "MCP GET SSE streams currently held open (each pins one HTTP worker)",
                          "gauge");
        // Deliberately a SEPARATE series from the GET gauge above rather than a
        // label on it: the two have different lifetimes (a GET channel is
        // open-ended, a streamed POST is bounded by its response cap) and
        // different owners, so summing them would hide which kind is saturating.
        metrics_.describe("yuzu_mcp_post_streams_active",
                          "MCP streamed-POST (SSE-on-POST) responses currently held open (each "
                          "pins one HTTP worker)",
                          "gauge");
        metrics_.describe("yuzu_http_held_open_responses",
                          "SSE responses held open right now across ALL surfaces (MCP GET, "
                          "MCP streamed POST, /api/v1/events, dashboard drawer, legacy /events) — "
                          "each pins one HTTP worker thread",
                          "gauge");
        metrics_.describe("yuzu_http_held_open_capacity",
                          "Held-open responses this server is sized for (--max-sse-streams, "
                          "clamped to the worker pool). Utilisation = responses / capacity",
                          "gauge");
        metrics_.describe("yuzu_http_worker_pool_size", "Shared HTTP worker pool size", "gauge");
        metrics_.gauge("yuzu_http_held_open_responses").set(0);
        metrics_.describe("yuzu_mcp_streams_handover_pending",
                          "Superseded MCP SSE streams still draining — each still pins a worker",
                          "gauge");
        // The EFFECTIVE cap, after the boot-time clamp. Without this an operator who set
        // --max-sse-streams and is being rejected at 12 has only a boot log line to
        // tell them why.
        metrics_.describe("yuzu_mcp_streams_cap",
                          "Effective concurrent MCP SSE stream cap after the worker-pool clamp",
                          "gauge");
        metrics_.describe("yuzu_mcp_stream_closes_total", "MCP SSE streams closed, by reason",
                          "counter");
        metrics_.describe("yuzu_mcp_stream_frames_dropped_total",
                          "Frames dropped before reaching a connection's per-connection queue — "
                          "usually a slow consumer's queue overflow, also a rare producer-side "
                          "post-commit allocation failure (#2366); recoverable via Last-Event-ID",
                          "counter");
        metrics_.describe("yuzu_mcp_stream_frames_too_large_total",
                          "Frames replaced by a frame_too_large notice because they exceeded the "
                          "per-session replay-ring byte budget",
                          "counter");
        metrics_.describe("yuzu_mcp_stream_replay_ring_evictions_total",
                          "Frames evicted from a session's bounded replay ring — a client whose "
                          "cursor falls behind gets a 404 and must re-initialize",
                          "counter");
        metrics_.describe("yuzu_mcp_stream_rejects_total",
                          // Covers the GET attach denials AND the streamed-POST
                          // ADMISSION denials (post_* reasons). It does NOT cover
                          // every streamed-POST refusal: a bridge-level reserve
                          // reject is counted by the bridge's own
                          // yuzu_mcp_bridge_reject_total. Two families, split by who
                          // refused, not by surface.
                          "MCP SSE stream denials by reason — GET attach denials plus "
                          "streamed-POST admission denials",
                          "counter");
        metrics_.describe("yuzu_mcp_initialize_protocol_total",
                          "MCP initialize handshakes by negotiated protocol revision", "counter");
        metrics_.describe("yuzu_mcp_cancel_notifications_total",
                          "notifications/cancelled received, by outcome: `detached` - a live "
                          "streamed response was ended by this cancel; `accepted` - intent "
                          "recorded before the request armed, for arm()/abandon() to arbitrate; "
                          "`noop` - nothing to cancel. A high noop rate means clients are "
                          "cancelling requests that already finished, addressing the wrong "
                          "session, or retrying a cancel that already landed. A cancel NEVER "
                          "stops the execution - it detaches the response only",
                          "counter");
        metrics_.describe("yuzu_mcp_stream_publish_failures_total",
                          "publish() exception-boundary catches — a producer's frame "
                          "construction failed before commit (#2366); the frame was never "
                          "published and no event id was consumed",
                          "counter");
        metrics_.describe("yuzu_mcp_tool_security_misconfig_total",
                          "MCP tools/call denials for a served tool with no security "
                          "registration (C8 fail-closed, #2383) — the boot validator makes "
                          "this state unbootable, so any non-zero value means it was "
                          "bypassed; alert on > 0 "
                          "(docs/ops-runbooks/mcp-tool-registration-recovery.md)",
                          "counter");
        metrics_.describe("yuzu_mcp_tool_args_invalid_total",
                          "MCP tools/call denials where the arguments failed the tool's "
                          "input schema before approval-ticket mint/consume (#2405); a "
                          "spike on one tool means a supervised worker is submitting "
                          "malformed arguments or probing",
                          "counter");
        // Progress bridge core (2f PR 3a). Same closed-set posture: every reject/
        // degrade reason is a static literal inside the bridge, never derived
        // from caller input.
        metrics_.describe("yuzu_mcp_bridge_records_active",
                          "Progress-bridge correlation records currently live (global cap 256)",
                          "gauge");
        metrics_.describe("yuzu_mcp_bridge_reject_total",
                          "Progress-bridge reservation rejections by reason", "counter");
        metrics_.describe("yuzu_mcp_bridge_degrade_total",
                          "execute_instruction progress requests silently degraded to the plain "
                          "path, by reason (the plain response is self-sufficient - it carries "
                          "execution_id)",
                          "counter");
        metrics_.describe("yuzu_mcp_bridge_listener_failures_total",
                          "Bus-listener copy failures contained at the noexcept boundary - the "
                          "event was not latched; the terminal backstop is the durable "
                          "execution_id fetch",
                          "counter");
        metrics_.describe("yuzu_mcp_bridge_mailbox_drops_total",
                          "Oldest-progress frames dropped from a record's bounded arming mailbox "
                          "(terminals are never dropped)",
                          "counter");
        metrics_.describe("yuzu_mcp_stream_terminal_publish_failures_total",
                          "Terminal-frame publish failures seen by the bridge's "
                          "publish_final → fallback → poison ladder (Decision 15(f))",
                          "counter");
        metrics_.describe("yuzu_mcp_bridge_projector_cycles_total",
                          "Progress-bridge projector wake cycles. An event-driven liveness signal: "
                          "records_active > 0 with a flat rate here means the projector is wedged",
                          "counter");
        metrics_.describe("yuzu_mcp_bridge_projection_degraded_total",
                          "Progress-bridge projections whose claim had to be released WITHOUT the "
                          "record lock, so the settle bookkeeping could not run normally (#2528). "
                          "Needs a genuinely broken platform mutex, so ANY nonzero value is a "
                          "signal, not a rate: the record is still reclaimable, but a terminal "
                          "payload mid-retry is lost and answered by the fallback final",
                          "counter");
        metrics_.describe("yuzu_mcp_stream_attach_audit_failures_total",
                          "Streamed-POST attach audits the sink REJECTED (returned false rather "
                          "than throwing). The stream is live and correct; its evidence is not. "
                          "Installing the content provider seals the response headers, so unlike "
                          "the GET channel there is no Sec-Audit-Failed to set and this counter "
                          "is the only signal. Any non-zero value is an audit-coverage gap",
                          "counter");
        metrics_.describe("yuzu_mcp_bridge_pin_slots_reject_total",
                          "Streamed admissions refused for want of a session slot, by which half "
                          "of the admission sum held them: held=\"charges\" means at least one "
                          "charge was outstanding; held=\"pins\" means finals already committed "
                          "whose pins were not yet released. After the rule-(a) unpin a "
                          "pins refusal should not PERSIST, so a sustained rate there is the "
                          "wedged-session signature - the case where the 429's own remediation "
                          "(\"wait for one to finish\") is untrue because they already did. A "
                          "single pins sample is NOT a wedge: the charge-to-pin handover happens "
                          "at terminal projection but the unpin only once the final reaches the "
                          "wire, so every healthy session passes through that shape during the "
                          "flush window - which is why its alert carries a load-bearing `for`. "
                          "And \"charges\" is not purely benign: it is emitted whenever ANY "
                          "charge is outstanding, so a PARTIAL wedge is bucketed there unseen",
                          "counter");
        metrics_.describe("yuzu_mcp_bridge_charge_release_deferred_total",
                          "Streamed admission charges that could not be released at their natural "
                          "release point and are RETAINED on the record until its teardown "
                          "reclaims them (#2529). Needs a genuinely broken platform mutex, so ANY "
                          "nonzero value is a signal, not a rate. The record and the ledger still "
                          "agree, so this is a deferred release, never a stranded slot",
                          "counter");
        metrics_.describe("yuzu_mcp_bridge_streaming_backstop_total",
                          "Streamed-POST records the sweep had to park because they were still "
                          "kStreaming with a dead session or long past the cap. The pump's own "
                          "releaser is what normally ends that phase, so any nonzero value means "
                          "a close was swallowed or never delivered - without this backstop the "
                          "record would leak for the life of the process",
                          "counter");
        metrics_.describe("yuzu_mcp_bridge_teardown_incomplete_total",
                          "Progress-bridge teardown steps that could not complete on the "
                          "maintenance thread, by reason. DEFENCE IN DEPTH, not the live "
                          "out-of-memory signal: all three steps allocate nothing, so only a "
                          "mutex failure can reach them today - use "
                          "yuzu_mcp_stream_terminal_publish_failures_total for allocation "
                          "pressure. The claim is one-way, so a record that fails here is never "
                          "retried and what it still owns is held until the process restarts; a "
                          "retained record also pins that session's whole stream state, its "
                          "replay ring and any pinned finals. Alert on > 0",
                          "counter");
        metrics_.describe("yuzu_mcp_bridge_forced_expire_total",
                          "Parked progress-bridge records force-expired by the ring-only "
                          "pressure escape hatch, by the disposition the visitor DECIDED "
                          "(#2489). Counted at the decision, before the teardown publishes, so "
                          "this is an attempted disposition and not proof of delivery - a frame "
                          "build, the publish ladder or the poison step can still fail "
                          "afterwards, which is what yuzu_mcp_stream_terminal_publish_failures_"
                          "total and yuzu_mcp_bridge_teardown_incomplete_total report. A claim "
                          "that loses a shutdown race is reaped by shutdown() and is NOT "
                          "counted here (the shutdown-silent convention in "
                          "docs/observability-conventions.md). \"none\": a real final was "
                          "already pinned, so the client loses nothing. \"fallback_final\": a "
                          "terminal DID happen but its payload is gone - either aged out of the "
                          "bus buffer, or lost to a degraded projection claim (#2528, see "
                          "yuzu_mcp_bridge_projection_degraded_total) - so a success-shaped "
                          "final pointing at execution_id is published instead. "
                          "\"synthesize_unavailable\": the bus verdict was that the execution "
                          "never reached a terminal, so -32014 is published. Movement means the "
                          "cap is doing its job; the previous only signal here was a FAILURE "
                          "counter, so a fleet quietly degrading every client to the fallback "
                          "and one synthesizing -32014 looked identical. Alert on a rising "
                          "synthesize_unavailable rate; for fallback_final check the "
                          "projection-degraded counter first, and only then treat it as a "
                          "bus-buffer sizing question",
                          "counter");
        metrics_.describe("yuzu_mcp_bridge_pressure_budget_exhausted_total",
                          "Ring-only pressure passes that stopped on their per-invocation "
                          "victim budget with the cap STILL exceeded (#2489 review). The budget "
                          "is the number of parked records the pass saw when it started, and it "
                          "exists because a deferred victim now advances the pass instead of "
                          "ending it - without it, records parking as fast as they are expired "
                          "would keep one maintenance tick working indefinitely and delay the "
                          "session GC that shares that thread. Not an error and not a loss: the "
                          "remaining victims are expired on the next tick. A sustained rate "
                          "means arrivals are keeping pace with expiries - look at "
                          "yuzu_mcp_bridge_records_active and the streamed-POST admission rate",
                          "counter");
        metrics_.describe("yuzu_mcp_maintenance_tick_failures_total",
                          "MCP maintenance ticks that threw and were contained, by tick "
                          "(#2487). The tick is skipped, not retried. bridge_sweep: pin-ack, "
                          "session-death and pressure teardown are all stalled while it grows. "
                          "session_gc: expired sessions keep their streams and pinned finals "
                          "until a tick succeeds. Both are guarded separately so one failing "
                          "cannot suppress the other",
                          "counter");
        metrics_.describe("yuzu_mcp_stream_final_unpinned_total",
                          "Committed terminal frames that found no free pin slot and were published "
                          "UNPINNED (a real terminal is committed rather than lost to preserve a "
                          "pin). Structurally unreachable while the pin array is non-empty - a "
                          "full slot set now displaces its oldest pin rather than committing the "
                          "NEWEST final unprotected. Kept as defence in depth: any non-zero value "
                          "means the pin array was resized to zero or the displacement path was "
                          "bypassed. Alert on > 0",
                          "counter");
        metrics_.describe("yuzu_mcp_stream_pin_displaced_total",
                          "An older pinned terminal yielded its eviction-exemption slot to a newer "
                          "one. NOT expected: the bridge admits streamed records against "
                          "pinned_count() + unpinned and the pin array is sized to exactly that "
                          "cap, so a full slot set means ADMISSION ACCOUNTING HAS DRIFTED - this "
                          "counter inherits the drift reading the unpinned counter used to carry. "
                          "The displacement itself is the graceful degradation (the oldest "
                          "terminal, likeliest already consumed, yields instead of the newest "
                          "going unprotected); the displaced final becomes evictable from the "
                          "replay ring, still recoverable by execution_id. Alert on > 0",
                          "counter");
        metrics_.gauge("yuzu_mcp_sessions_active").set(0);
        metrics_.counter("yuzu_mcp_sessions_opened_total");
        metrics_.gauge("yuzu_mcp_streams_active").set(0);
        metrics_.gauge("yuzu_mcp_post_streams_active").set(0);
        metrics_.gauge("yuzu_mcp_streams_handover_pending").set(0);
        metrics_.gauge("yuzu_mcp_bridge_records_active").set(0);
        metrics_.counter("yuzu_mcp_bridge_listener_failures_total");
        metrics_.counter("yuzu_mcp_bridge_mailbox_drops_total");
        metrics_.counter("yuzu_mcp_bridge_projector_cycles_total");
        metrics_.counter("yuzu_mcp_bridge_projection_degraded_total");
        metrics_.counter("yuzu_mcp_stream_attach_audit_failures_total");
        for (auto held : {"charges", "pins"}) {
            metrics_.counter("yuzu_mcp_bridge_pin_slots_reject_total", {{"held", held}});
        }
        metrics_.counter("yuzu_mcp_bridge_charge_release_deferred_total");
        metrics_.counter("yuzu_mcp_bridge_streaming_backstop_total");
        metrics_.counter("yuzu_mcp_stream_terminal_publish_failures_total");
        metrics_.counter("yuzu_mcp_stream_final_unpinned_total");
        metrics_.counter("yuzu_mcp_stream_pin_displaced_total");
        // Pre-seed the CLOSED reason label sets to 0 so absent() alerting is
        // meaningful on a healthy/idle server (observability-conventions; the
        // reason literals mirror the bridge's reject/degrade taxonomies).
        for (auto reason : {"disabled", "unknown_session", "shutdown", "duplicate_request_id",
                            "global_cap", "pin_slots"}) {
            metrics_.counter("yuzu_mcp_bridge_reject_total", {{"reason", reason}});
        }
        // Derived from the bridge's own CLOSED list so a new degrade reason cannot
        // be emitted without this seed following it - the streamed-POST rung added
        // six and seeded none, which left valid series absent on a healthy server.
        for (auto reason : mcp::McpStreamBridge::kDegradeReasons) {
            metrics_.counter("yuzu_mcp_bridge_degrade_total", {{"reason", reason}});
        }
        // #2487: CLOSED reason set, derived from the bridge's own stage table so a
        // fourth owned resource cannot be added without this loop following.
        for (auto stage : mcp::McpStreamBridge::kTeardownStageNames) {
            metrics_.counter("yuzu_mcp_bridge_teardown_incomplete_total", {{"reason", stage}});
        }
        // sre-N1 (#2489): CLOSED set, derived from TeardownFinal the same way, so a
        // fourth disposition cannot ship without this seed following it. Seeding
        // matters more here than elsewhere: an idle server force-expires nothing,
        // and an absent series reads as "never happened" exactly where the
        // operator needs "has not happened YET".
        for (auto disposition : mcp::McpStreamBridge::kForcedExpireDispositions) {
            metrics_.counter("yuzu_mcp_bridge_forced_expire_total",
                             {{"disposition", disposition}});
        }
        metrics_.counter("yuzu_mcp_bridge_pressure_budget_exhausted_total");
        for (auto tick : {"bridge_sweep", "session_gc"}) {
            metrics_.counter("yuzu_mcp_maintenance_tick_failures_total", {{"tick", tick}});
        }
        metrics_.counter("yuzu_mcp_stream_frames_dropped_total");
        metrics_.counter("yuzu_mcp_stream_frames_too_large_total");
        metrics_.counter("yuzu_mcp_stream_publish_failures_total");
        metrics_.counter("yuzu_mcp_tool_security_misconfig_total");
        // Pre-seed the #2405 schema-denial counter for every approval-gated
        // tool — the closed label set that can reach the gate — so absent()
        // alerts stay meaningful (observability-conventions.md).
        for (const auto& tool : mcp::approval_gated_tool_names()) {
            metrics_.counter("yuzu_mcp_tool_args_invalid_total", {{"tool", tool}});
        }
        // #2437 handler-side bound denials. The label set is closed on BOTH
        // axes: `tool` is execute_instruction alone (the only tool that EMITS
        // this counter today; the two kAgenticParamMaxLen read tools bound in
        // the handler but audit without a metric) and `reason` is the fixed
        // literal set below - so this pre-seed is exhaustive and absent() stays
        // meaningful. Extend both lists together if a second tool gains bounds.
        // Iterated from the ONE array in mcp_input_bounds.hpp rather than
        // restated here: a second literal list is how a new rule ends up
        // emitted-but-unseeded, which passes its own test and silently breaks
        // absent() alerting. This commit's six targeting reasons went into
        // that array, not into a list here - which is the tether working.
        for (const auto reason : yuzu::server::mcp::kExecInstrBoundReasons) {
            metrics_.counter("yuzu_mcp_tool_args_too_large_total",
                             {{"tool", "execute_instruction"}, {"reason", std::string(reason)}});
        }
        // #2500 REST targeting refusals. Deliberately NOT the MCP counter above:
        // these are different surfaces with different gates, and folding them into
        // one series would make `yuzu_mcp_*` count calls that never touched MCP.
        // Both axes are closed — `route` is the REST surfaces that dispatch or
        // narrow on caller-supplied targeting, `reason` iterates the ONE array in
        // dispatch_target_shape.hpp — so this pre-seed is exhaustive and absent()
        // stays meaningful. A reason added at an emit site instead of in that array
        // is emitted-but-unseeded: it passes its own test while the dashboard reads
        // zero and the alert never fires.
        metrics_.describe("yuzu_server_dispatch_target_rejected_total",
                          "REST dispatch calls refused because a supplied targeting argument "
                          "named no device, plus dispatch-closure calls that named no target at "
                          "all (#2500). Both labels are closed sets; every reachable pair is "
                          "pre-seeded at boot so absent() stays meaningful.",
                          "counter");
        // The route-level reasons below are the literals in `kRouteRejectReasons`
        // (dispatch_target_shape.hpp). They are spelled out here rather than
        // iterated because each applies to a DIFFERENT route subset, and a
        // single loop over the array would seed unreachable pairs — which is
        // exactly what the per-route seeding fixes. `test_dispatch_target_shape.cpp`
        // binds the two lists so a reason added at an emit site without a home
        // in the array fails a test.
        //
        // Seeded PER ROUTE rather than as a cross-product: `result_set_parent`
        // can only ever emit the two parent_id reasons, and the dispatch routes
        // can never emit them. Seeding the full product would publish series
        // that no code path can reach, which reads on a dashboard as "this has
        // never happened" when the truth is "this cannot happen" (governance).
        for (const char* route : {"command", "instruction_execute"}) {
            for (const auto reason : yuzu::server::kTargetingShapeReasons)
                metrics_.counter("yuzu_server_dispatch_target_rejected_total",
                                 {{"route", route}, {"reason", std::string(reason)}});
            metrics_.counter("yuzu_server_dispatch_target_rejected_total",
                             {{"route", route},
                              {"reason", std::string(yuzu::server::kReasonBodyType)}});
        }
        for (const auto reason : {yuzu::server::kReasonParentIdType,
                                  yuzu::server::kReasonParentIdEmpty})
            metrics_.counter("yuzu_server_dispatch_target_rejected_total",
                             {{"route", "result_set_parent"}, {"reason", std::string(reason)}});
        // `policy_remediate` has its OWN reachable set, not the dispatch routes'.
        // It refuses `scope` outright (PolicyEvaluator::remediate takes only
        // agent_ids), so `scope_type`, `scope_empty` and `target_conflict` can
        // never be emitted there — seeding them would publish series no code
        // path can reach, which reads on a dashboard as "never happened" when
        // the truth is "cannot happen".
        for (const auto reason : {yuzu::server::kReasonBodyType,
                                  yuzu::server::kReasonScopeUnsupported,
                                  yuzu::server::kReasonAgentIdsType,
                                  yuzu::server::kReasonAgentIdsEmpty,
                                  yuzu::server::kReasonAgentIdType}) {
            metrics_.counter("yuzu_server_dispatch_target_rejected_total",
                             {{"route", "policy_remediate"}, {"reason", std::string(reason)}});
        }
        // The shared dispatch closure's last-line-of-defence arm. Its own route
        // label because it is not a REST surface — background runners reach it
        // too — and a non-zero value here means a CALLER forgot to name a
        // target, which is a code defect rather than a client one.
        metrics_.counter("yuzu_server_dispatch_target_rejected_total",
                         {{"route", "dispatch_closure"},
                          {"reason", std::string(yuzu::server::kReasonClosureNoTarget)}});
        // #2437 transport-layer body rejection (pre-routing, pre-auth). No
        // `tool` label: the body is never read, so nothing is known about the
        // call beyond its path — a tool label here would be a fabrication.
        // `reason` distinguishes a measured over-cap body (413) from one this
        // server refuses to measure at all (411: chunked, or POST with no
        // Content-Length — both would otherwise revert to httplib's 100 MB
        // default and evade the cap entirely).
        for (auto reason : {"over_cap", "unmeasurable"}) {
            metrics_.counter("yuzu_mcp_body_too_large_total", {{"reason", reason}});
        }
        for (auto reason : {"client_disconnect", "superseded", "session_terminated",
                            "credential_revoked", "auth_unavailable", "internal_error",
                            // 2f PR 3b streamed-POST close reasons — producers land in C6c/C7;
                            // pre-seeded here so the closed label set is complete from C4.
                            "cancelled", "cap_expired", "completed"}) {
            metrics_.counter("yuzu_mcp_stream_closes_total", {{"reason", reason}});
        }
        metrics_.counter("yuzu_mcp_stream_replay_ring_evictions_total");
        // Derived from the bridge's own CLOSED list, beside the enum - a
        // hand-written copy here is what let `detached` ship unseeded.
        for (auto outcome : mcp::McpStreamBridge::kCancelOutcomeLabels) {
            metrics_.counter("yuzu_mcp_cancel_notifications_total", {{"outcome", outcome}});
        }
        for (auto reason : {"missing_session_header", "unknown_session", "not_acceptable",
                            "per_principal_stream_cap", "global_stream_cap",
                            "stream_handover_pending", "replay_window_exceeded", "origin",
                            }) {
            metrics_.counter("yuzu_mcp_stream_rejects_total", {{"reason", reason}});
        }
        // 2f PR 3b streamed-POST admission denials, derived from the bridge's own
        // closed list so the emit sites and this seed cannot drift. Prefixed `post_`
        // because they answer a DIFFERENT question from the GET labels above: which
        // admission gate refused a streamed tool call, not which attach check
        // refused a channel.
        for (auto reason : mcp::McpStreamBridge::kPostRejectReasons) {
            metrics_.counter("yuzu_mcp_stream_rejects_total", {{"reason", reason}});
        }
        // Pre-seed both supported MCP protocol revisions to 0 so a
        // revision-deprecation dashboard reads "0" (not absent) for an unused
        // revision (observability-conventions.md; 2g PR 1). Values mirror the
        // supported set in mcp_transport.cpp (protocol_version_supported).
        for (auto revision : {"2025-03-26", "2025-06-18"}) {
            metrics_.counter("yuzu_mcp_initialize_protocol_total", {{"revision", revision}});
        }
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
        // Birth the series with the extended 10-60s buckets ONCE here (#1686) so the
        // hot per-acquire observe path uses the cheap name-only lookup and never
        // allocates a throwaway bucket vector per acquire.
        metrics_.histogram("yuzu_pg_acquire_wait_seconds", yuzu::Histogram::seconds_buckets_60s());
        // Installed-software inventory observability (ADR-0016; #1664/#1675).
        metrics_.describe("yuzu_inventory_ingest_total",
                          "Inventory-report ingest outcomes by source and outcome "
                          "(stored/touched/need_full/error/dropped/rejected)",
                          "counter");
        metrics_.describe("yuzu_inventory_ingest_duration_seconds",
                          "Time to apply one inventory source's report — the pooled-connection + "
                          "transaction hold time per ingest, by source and phase "
                          "(full = full-payload replace; hash_only = hash-skip compare)",
                          "histogram");
        metrics_.describe("yuzu_inventory_read_degrade_total",
                          "Authoritative inventory reads that returned a degrade (no data) rather "
                          "than a result, by reason "
                          "(store_not_open/pool_acquire_timeout/query_error) and source "
                          "(installed_software/device_ci/software_licensing/product_registry/"
                          "generic — generic is the ADR-0037 InventoryStore). /readyz stays "
                          "green under pure pool saturation, so "
                          "this is the read-path degrade signal",
                          "counter");
        // Management-group CONFINEMENT store observability (ADR-0042). The
        // read-degrade counter is the fail-closed signal: a non-zero rate means
        // RbacStore's authorize_list_read / check_scoped_permission is denying
        // because the confinement substrate could not answer (store_not_open /
        // pool_acquire_timeout / query_error). /readyz stays green under pure
        // pool saturation, so this is the read-path degrade signal.
        metrics_.describe("yuzu_server_mgmt_group_read_degrade_total",
                          "Management-group confinement reads (get_agent_groups / "
                          "get_ancestor_ids / get_descendant_ids / get_member_agents_in_subtrees "
                          "/ get_assignments_for_principal / get_visible_agents) that returned a "
                          "degrade (nullopt/DenyAll) rather than a result, by reason "
                          "(store_not_open/pool_acquire_timeout/query_error)",
                          "counter");
        for (const auto reason : {"store_not_open", "pool_acquire_timeout", "query_error"})
            metrics_.counter("yuzu_server_mgmt_group_read_degrade_total", {{"reason", reason}});
        metrics_.describe("yuzu_server_mgmt_group_backfill_total",
                          "Management-group legacy-SQLite backfill outcomes by result "
                          "(completed = rows migrated + reconciled; fresh = no legacy DB / empty; "
                          "failed = fail-closed refusal). One-time at boot (ADR-0042)",
                          "counter");
        for (const auto result : {"completed", "fresh", "failed"})
            metrics_.counter("yuzu_server_mgmt_group_backfill_total", {{"result", result}});
        // Generic InventoryStore observability (ADR-0037 hardening round).
        metrics_.describe(
            "yuzu_inventory_ingest_dropped_total",
            "Generic InventoryStore upsert calls that did not persist, by reason "
            "(store_not_open/pool_acquire_timeout/query_error/invalid_key/stale) — the next "
            "changed/full report re-sends the blob (weekly full floor), but a sustained "
            "non-zero rate means writes are silently not landing",
            "counter");
        // Closed reason dimension: seed every reachable path so an idle or
        // newly-started server exports zeros and absent-series alerting remains
        // distinguishable from a scrape/configuration failure.
        for (const auto reason : {"store_not_open", "pool_acquire_timeout", "query_error",
                                  "invalid_key", "stale"})
            metrics_.counter("yuzu_inventory_ingest_dropped_total", {{"reason", reason}});
        metrics_.describe("yuzu_inventory_query_truncated_total",
                          "Generic InventoryStore query() calls whose result hit the effective "
                          "row limit or aggregate byte cap — more rows may exist past what was "
                          "returned",
                          "counter");
        metrics_.describe("yuzu_inventory_stale_agents",
                          "Agents whose installed-software inventory has not synced within the "
                          "staleness window (two missed daily cycles) — a freshness/liveness signal, "
                          "by source",
                          "gauge");
        metrics_.describe("yuzu_inventory_stale_count_unavailable_total",
                          "Times the stale-agents freshness count could not be computed (pool "
                          "saturation / query timeout) and the yuzu_inventory_stale_agents gauge "
                          "was held at its prior value — a non-zero rate means that gauge may be "
                          "frozen, not genuinely low",
                          "counter");
        // DEX app-perf-over-time (B1/B2) — ingest, rollup, and read-degrade signals.
        // Described up front so the HELP/TYPE lines exist on an idle server (a
        // low-traffic deployment otherwise ships these series invisible until the
        // first event).
        metrics_.describe("yuzu_app_perf_ingest_total",
                          "DEX app-perf daily-sync ingest outcomes by outcome "
                          "(stored/need_full/dropped/error)",
                          "counter");
        metrics_.describe("yuzu_app_perf_ingest_duration_seconds",
                          "Time to apply one agent's app-perf daily report (pooled-connection + "
                          "upsert hold time)",
                          "histogram");
        metrics_.describe("yuzu_app_perf_rollup_total",
                          "B1->B2 app-perf roll-up outcomes per day rolled, by outcome "
                          "(success/fail)",
                          "counter");
        metrics_.describe("yuzu_app_perf_rollup_duration_seconds",
                          "Time to roll one completed UTC day from B1 (per-device daily) into B2 "
                          "(fleet aggregate + histogram)",
                          "histogram");
        metrics_.describe("yuzu_app_perf_rollup_last_success_timestamp",
                          "Epoch seconds of the last successful B1->B2 roll-up. The sole writer of "
                          "the 180-day B2 trend store; alert when now - this exceeds the roll-up "
                          "cadence (a stuck/failing rollup thread leaves B2 silently stale)",
                          "gauge");
        metrics_.describe("yuzu_inventory_catalog_rollup_total",
                          "/inventory Software-tab catalogue rollup recompute outcomes, by outcome "
                          "(success/error). Keep-last-good on error.",
                          "counter");
        metrics_.describe("yuzu_inventory_catalog_rollup_duration_seconds",
                          "Wall-clock of the last catalogue rollup recompute (the full-table "
                          "GROUP BY, off the request path)",
                          "gauge");
        metrics_.describe("yuzu_inventory_catalog_rollup_last_success_timestamp",
                          "Epoch seconds of the last successful catalogue rollup refresh; alert when "
                          "now - this exceeds the rollup cadence (a stuck/failing thread leaves the "
                          "/inventory catalogue silently stale)",
                          "gauge");
        metrics_.describe("yuzu_app_perf_read_degrade_total",
                          "Authoritative B1 (per-device app-perf) reads that returned a degrade "
                          "rather than a result, by reason "
                          "(store_not_open/pool_acquire_timeout/query_error)",
                          "counter");
        metrics_.describe("yuzu_app_perf_fleet_read_degrade_total",
                          "Authoritative B2 (fleet app-perf) reads that returned a degrade rather "
                          "than a result, by reason",
                          "counter");
        metrics_.describe("yuzu_app_perf_group_read_degrade_total",
                          "Management-group app-perf trend reads that returned a degrade rather than "
                          "a result, by reason",
                          "counter");
        metrics_.describe("yuzu_app_perf_cohort_read_degrade_total",
                          "/auto VERIFY cohort B1 reads that returned a degrade rather than a "
                          "result, by reason (pool_acquire_timeout/query_error)",
                          "counter");
        metrics_.describe("yuzu_app_perf_cohort_read_cap_hit_total",
                          "/auto VERIFY cohort reads that hit the row cap and were TRUNCATED (the "
                          "comparison is incomplete and may mis-pair machines)",
                          "counter");
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
        // ADR-0010 §Decision 3. Carried in the gauge family because the
        // authoritative cumulative count lives in SecretCodec and is exported
        // pull-model at scrape time, but it IS a monotonic counter — declared
        // as one here so the scrape emits `# TYPE ... counter` and the `_total`
        // suffix matches docs/observability-conventions.md.
        metrics_.describe("yuzu_server_secret_decrypt_failures_total",
                          "Envelope-encrypted secret decrypt failures by store and failure class "
                          "(tamper, unresolvable KEK, malformed blob)",
                          "counter");
        // #2530 B7 — KEK rotate/rewrap/status observability. The four gauges
        // are sampled from Postgres cluster state on health_recompute_thread_
        // (15s cadence); the counter follows the same pull-model-carried-as-
        // counter pattern as yuzu_server_secret_decrypt_failures_total above
        // (the authoritative cumulative total lives in kek_op_outcome_counts_,
        // incremented at each kek_ops.{rotate,rewrap,status} return point).
        metrics_.describe("yuzu_server_kek_op_lock_held",
                          "Whether the cluster-wide secrets_kek_op advisory lock currently has a "
                          "granted holder (1) or not (0). A diagnostic snapshot, not a "
                          "safe-to-retire signal (#2525).",
                          "gauge");
        metrics_.describe("yuzu_server_kek_live_versions",
                          "Count of non-retired KEK versions (secrets.kek_meta rows with "
                          "retired_at IS NULL). Compare against --kek-max-live-versions.",
                          "gauge");
        // #2530 G8-S12: the configured --kek-max-live-versions ceiling,
        // exported as its OWN gauge so YuzuKekCeilingApproaching (below) can
        // alert on the RATIO yuzu_server_kek_live_versions /
        // yuzu_server_kek_max_live_versions instead of a hardcoded 32 —
        // retirement is impossible under #2525, so this ceiling is a
        // lifetime cap, and without this an operator who has already raised
        // the flag (the supported #2530 B5 escape hatch) gets no
        // proximity warning before hitting the NEW ceiling's 409. A static
        // config value, not sampled from Postgres — set once here, at boot,
        // so it stays published even when the KEK substrate itself is never
        // reachable (unlike the four gauges above, which are sampled from
        // cluster state on health_recompute_thread_ and can legitimately be
        // absent or frozen on a degrade).
        metrics_.describe("yuzu_server_kek_max_live_versions",
                          "The configured --kek-max-live-versions ceiling. A static config "
                          "value (set once at boot), not sampled from Postgres like the other "
                          "yuzu_server_kek_* gauges. Compare against "
                          "yuzu_server_kek_live_versions to gauge ceiling proximity.",
                          "gauge");
        metrics_.gauge("yuzu_server_kek_max_live_versions")
            .set(static_cast<double>(cfg_.kek_max_live_versions));
        metrics_.describe("yuzu_server_kek_active_version",
                          "The KEK version new secret encrypts currently use (the newest "
                          "non-retired kek_meta version).",
                          "gauge");
        // #2530 G7-B4: `yuzu_server_kek_oldest_version_in_use` was RETIRED —
        // it was fed only by the 15s health_recompute_thread_ sampler, which
        // dropped it (the query is the unbatched full-column scan whose
        // scale ceiling #2530 explicitly deferred; running it every 15s
        // instead of only on operator demand made that deferred problem
        // worse, not better). `GET /status`'s `oldest_in_use` field is
        // unaffected — it still computes this value on demand, which is
        // where it belongs.
        metrics_.describe("yuzu_server_kek_operations_total",
                          "KEK rotate/rewrap/status attempts by op and outcome (success, "
                          "conflict, cooldown, ceiling, query_canceled, clock_anomaly, "
                          "half_committed, unavailable, internal).",
                          "counter");
        // #2530 G7-S5: pre-seed the closed {op x outcome} vocabulary to 0
        // (same closed-label-set pre-seed pattern as
        // yuzu_server_principal_quota_exhausted_total below), so an outcome
        // that has never fired — "ceiling" or "clock_anomaly" being the
        // interesting ones — reads as a true zero, distinguishable from "not
        // wired up at all". Bounded: 3 ops x 9 outcomes = 27 series.
        for (auto kek_op : {"rotate", "rewrap", "status"}) {
            for (auto outcome : {"success", "conflict", "cooldown", "ceiling", "query_canceled",
                                 "clock_anomaly", "half_committed", "unavailable", "internal"}) {
                metrics_.gauge("yuzu_server_kek_operations_total",
                               {{"op", kek_op}, {"outcome", outcome}});
            }
        }
        metrics_.describe("yuzu_server_kek_metrics_unavailable_total",
                          "KEK cluster-state reads (health_recompute_thread_, #2530 G8-S2: "
                          "short-circuited after the first failure within a sweep, so this is "
                          "at most one increment per 15s sweep) that could not read Postgres; "
                          "on each occurrence every KEK gauge above HOLDS its prior published "
                          "value rather than publishing a false 0.",
                          "counter");
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
                          "gauge, so Windows is absent here", "gauge");
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
        // SparkEngine fleet telemetry (ADR-0021 Stage-2 rung 1 — OBSERVE-ONLY). All
        // os-labelled (per-OS, never a cross-OS blend — File/Registry are Windows-only,
        // Service is Windows+Linux, macOS has none). ABSENT means no reporting agent of
        // that OS/mechanism this cycle — never read absence as 0-is-healthy. At rung 1
        // (no consumer armed) every counter is 0, so only reporting + mechanisms +
        // failed/disabled carry signal; the counters go live at rung 2. ALERTING: the
        // counter-derived gauges are a fleet SUM of cumulative per-agent counters — a
        // bare `> 0` LATCHES forever once any agent ever counted one, and counter-typing
        // the fleet sum is not implementable server-side (it needs per-agent deltas and
        // a server-owned counter, #2083) — so their alert templates ship COMMENTED OUT
        // until rung 2 (see the spark preamble in docs/prometheus/yuzu-alerts.yml). The
        // exception is yuzu_fleet_spark_failed: a STATE gauge recomputed and cleared
        // every sweep, live-actionable at rung 1 — its `> 0 for: 30m` rule ships ACTIVE.
        metrics_.describe("yuzu_fleet_spark_reporting",
                          "Agents (per `os`) whose latest heartbeat reported the SparkEngine "
                          "running (spark_running=1) - the denominator for all spark telemetry",
                          "gauge");
        metrics_.describe("yuzu_fleet_spark_disabled",
                          "Agents (per `os`) running with SparkEngine deliberately off "
                          "(--spark-disable). An operator decision - expected to be non-zero; "
                          "do NOT alert on it", "gauge");
        metrics_.describe("yuzu_fleet_spark_failed",
                          "Agents (per `os`) where SparkEngine was ENABLED but boot-time "
                          "instantiation THREW, so the agent degraded to no-spark. Distinct from "
                          "`disabled` on purpose: this is a fault, not a choice - ALERT on it. "
                          "Absent = no agent of that os reported a failure this cycle", "gauge");
        metrics_.describe("yuzu_fleet_spark_mechanisms",
                          "Agents (per {`os`,`mechanism`}) whose spark capability includes that "
                          "event-driven mechanism (file / registry / service). An OS with agents "
                          "reporting but no {mechanism} series does not support it (e.g. no file "
                          "on linux)", "gauge");
        metrics_.describe("yuzu_fleet_spark_armed_faulted",
                          "Fleet sum (per `os`) of armed spark watches a mechanism reported deaf "
                          "(a live gauge, not cumulative). > 0 means detection is silently down "
                          "for that many watches", "gauge");
        metrics_.describe("yuzu_fleet_spark_watch_faults",
                          "Fleet sum (per `os`) of cumulative post-arm watch-fault edges "
                          "(watch_faults_total)", "gauge");
        metrics_.describe("yuzu_fleet_spark_queued_dropped",
                          "Fleet sum (per `os`) of cumulative queued events dropped (bounded-queue "
                          "overflow + shutdown). On the enforce lane (rung 3) a drop is a silent "
                          "compliance failure", "gauge");
        metrics_.describe("yuzu_fleet_spark_consumer_errors",
                          "Fleet sum (per `os`) of cumulative queued handlers that threw "
                          "(consumer_errors_total)", "gauge");
        metrics_.describe("yuzu_fleet_spark_watch_rejected",
                          "Fleet sum (per {`os`,`mechanism`}) of cumulative watch-cap rejections - "
                          "a rule that could not arm (denial-of-detection)", "gauge");
        metrics_.describe("yuzu_fleet_spark_quarantined",
                          "Fleet sum (per {`os`,`mechanism`}) of cumulative mechanism quarantines - "
                          "a structural leak that should stay 0; any value is page-worthy", "gauge");
        metrics_.describe("yuzu_fleet_spark_slow_op",
                          "Fleet sum (per {`os`,`mechanism`}) of cumulative slow watch/unwatch ops "
                          "(a stalled watcher)", "gauge");
        // Guardian durable lifecycle-journal fleet rollup (#2298 gate 3). Registered from
        // the SAME table AgentHealthStore::recompute_metrics clears and publishes from
        // (guardian_journal_fleet_tags.hpp), so a new signal cannot ship with a gauge but
        // no HELP, or with HELP that drifts from what the rollup actually computes.
        // Unlabelled by design; all 30 are ABSENT until some agent's journal reports.
        // Read the type-honesty note on kGuardianJournalMetrics before writing an
        // alert: no sound alerting form exists over these fleet sums yet (neither
        // increase() nor bare `> 0` survives a churning population), so the 30 are
        // MONITOR-ONLY until a per-agent axis lands (#2083-class; see the note).
        for (const auto& m : detail::kGuardianJournalMetrics)
            metrics_.describe(m.gauge, m.help, "gauge");
        // The journal AGE family (item 6 + #2364) - its own table because it rolls up
        // as MAX, not SUM (a fleet sum of ages is meaningless; see the table comment in
        // guardian_journal_fleet_tags.hpp for the emission differences too).
        for (const auto& m : detail::kGuardianJournalAgeMetrics)
            metrics_.describe(m.gauge, m.help, "gauge");
        // The two meta-signals are NOT in that table (it is pinned 1:1 to the agent's
        // GuardianJournalStats) and are published every sweep including at 0.
        metrics_.describe(detail::kGuardianJournalReportingGauge,
                          detail::kGuardianJournalReportingHelp, "gauge");
        metrics_.describe(detail::kGuardianJournalTagRejectedGauge,
                          detail::kGuardianJournalTagRejectedHelp, "gauge");
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
        // #2367 engine-principal liveness cache — same shape as the token
        // siblings above, described so the families ship typed and with HELP
        // rather than as bare untyped samples.
        metrics_.describe("yuzu_server_engine_revalidate_cache_hits_total",
                          "Engine-principal stream liveness re-checks served from cache",
                          "counter");
        metrics_.describe("yuzu_server_engine_revalidate_cache_misses_total",
                          "Engine-principal stream liveness re-checks that read through to "
                          "PostgreSQL",
                          "counter");
        metrics_.describe("yuzu_server_engine_revalidate_cache_size",
                          "Engine principals with a live (unexpired) liveness cache entry",
                          "gauge");
        metrics_.describe("yuzu_server_engine_revalidate_backoff_suppressed_total",
                          "Engine-principal liveness re-checks answered StoreUnreachable from the "
                          "failure backoff without taking a connection lease",
                          "counter");
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
        // #2360 retention clock guard. The two counters answer DIFFERENT
        // questions and must not be collapsed: skips means the guard declined a
        // delete that would have wiped the evidence table (this server's clock
        // moved), failed means the cleanup pass itself errored. Both leave rows
        // undeleted, so without the second an operator watching an audit table
        // that never shrinks would read a broken cleanup loop as a working guard.
        metrics_.describe("yuzu_server_audit_clock_anomaly_skips_total",
                          "Audit retention passes declined. A declined pass warns "
                          "and deletes NOTHING; one increment per declined pass. "
                          "Triggers: the pass would have expired every datable "
                          "row; the gap since the previous pass exceeded a fixed 7 "
                          "days (a forward clock jump OR an outage that long); or "
                          "the stored reading was not usable - ahead of the clock, "
                          "negative, present but not an integer, or unreadable. "
                          "Reducing audit_retention_days can also cause a decline "
                          "by design. Triage: "
                          "docs/user-manual/audit-log.md#the-retention-clock-guard. "
                          "The decision rule itself is classify() in "
                          "audit_retention_rules.hpp plus the fact construction in "
                          "AuditStore::cleanup_once, pinned by tests - it is "
                          "deliberately not paraphrased here",
                          "counter");
        metrics_.describe("yuzu_server_audit_retention_bootstrap_declines_total",
                          "Audit retention passes declined because there was no usable previous "
                          "clock reading to compare against AND rows were already expired "
                          "(#2579). Counted apart from the clock-anomaly series on purpose: this "
                          "decline does NOT claim the clock moved, only that nothing can yet "
                          "rule it out, so it must not fire an alert that says otherwise. "
                          "Expect 0 or 1 per database - the declining pass also anchors the "
                          "reading, so the next pass proceeds. A value that keeps climbing "
                          "means the anchor is not surviving; check "
                          "yuzu_server_audit_retention_persist_failed_total. Triage: "
                          "docs/user-manual/audit-log.md#the-retention-clock-guard",
                          "counter");
        metrics_.describe("yuzu_server_audit_cleanup_failed_total",
                          "Audit retention passes that did not fully do their job: an unreadable "
                          "probe, a failed delete, a refused implausible clock, a closed store, or "
                          "an exception caught at the thread boundary. Note one site fires AFTER a "
                          "successful delete (the post-delete backlog probe), so this means "
                          "'retention is not fully healthy', not 'nothing was deleted'",
                          "counter");
        // The cap that makes an allowed wipe pace out introduces its own failure
        // mode: if it binds on EVERY pass for a sustained period, expiry is
        // outrunning the drain and audit.db grows without bound. Neither counter
        // above moves in that state, so this pair is the only way it is visible.
        // Counted rather than measured with a COUNT(*) backlog gauge on purpose
        // -- that query would scan under the same lock every audit write takes.
        metrics_.describe("yuzu_server_audit_rows_deleted_total",
                          "Audit rows deleted by retention", "counter");
        metrics_.describe("yuzu_server_audit_retention_cap_reached_total",
                          "Audit retention passes that hit the per-pass delete cap, leaving a "
                          "backlog for the next pass",
                          "counter");
        // Liveness. Every other retention series is silence-means-healthy, so a
        // cleanup thread that never runs leaves them all flat at 0 -- identical
        // to a quiet, healthy store, while audit.db grows without bound. These
        // two are what an operator alerts on the ABSENCE of.
        metrics_.describe("yuzu_server_audit_retention_passes_total",
                          "Audit retention passes attempted, including declined and failed ones. "
                          "Flat means the cleanup thread is not running - the one condition the "
                          "other retention counters cannot report",
                          "counter");
        metrics_.describe("yuzu_server_audit_retention_last_pass_unixtime",
                          "Wall-clock reading of the most recent audit retention pass WHOSE CLOCK "
                          "WAS USABLE; 0 if none has run in this process. Read WITH "
                          "retention_passes_total: stale here while that RISES means the reaper "
                          "is alive but refusing an implausible clock, which is a different fault "
                          "from stopped",
                          "gauge");
        metrics_.describe("yuzu_server_audit_retention_persist_failed_total",
                          "Failures to persist the audit retention clock reading, which degrades "
                          "clock-anomaly detection across a restart",
                          "counter");
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
                          "(stolen-token impersonation attempt)",
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
                          "(leaked token presented by a second agent)",
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
                          "accommodation instead of rejected. Labelled event=security "
                          "(SIEM-routing tag) and reason (mtls_identity_match|trusted_nat_cidr)",
                          "counter");
        metrics_.describe("yuzu_register_denied_total",
                          "Register/ProxyRegister rejected an admin-denied agent before "
                          "consuming its enrollment token. Labelled source "
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
        // Durable SSO identity provisioning observability (#1852 governance
        // round, sec-LOW/UP-5). Incremented on every successful
        // upsert_sso_identity call (first-provision AND re-login refresh),
        // labelled by source so an IdP-side provisioning flood is visible
        // independently of ordinary login volume.
        metrics_.describe("yuzu_auth_sso_provision_total",
                          "Total durable SSO identity provision/refresh upserts, by source",
                          "counter");
        // Fail-closed-path observability (governance hardening round,
        // sre BLOCKING). Every 503 an operator/agentic worker sees from a
        // `is_store_unavailable` guard on the auth/MFA surface increments
        // this, labelled by the route that hit it — so a PG/KEK outage is
        // visible as a metric spike distinct from ordinary 401/403 traffic,
        // and SRE can tell WHICH fail-closed path is degraded. Bounded,
        // pre-seeded closed label set (route) per
        // docs/observability-conventions.md, so absent() alerts stay
        // meaningful.
        metrics_.describe("yuzu_auth_secret_unavailable_total",
                          "Total requests refused 503 by an is_store_unavailable fail-closed "
                          "guard on the auth/MFA surface, by route",
                          "counter");
        for (auto route : {"login", "mfa_verify", "mfa_stepup", "mfa_enroll", "elevate"}) {
            metrics_.counter("yuzu_auth_secret_unavailable_total", {{"route", route}});
        }
        // First-boot seed observability (authdb MEDIUM). Incremented exactly
        // once, iff `seed_admin_if_empty` actually seeded the sole admin row
        // (an empty `auth.users` table) — a no-op (table already populated,
        // the common case on every restart) leaves this at 0. No labels: the
        // event is binary and rare enough that a plain counter (0 forever, or
        // 1 after the one genuine fresh-start boot) is the whole signal.
        metrics_.describe("yuzu_auth_fresh_start_reset_total",
                          "1 iff this boot seeded the sole admin user into an empty auth.users "
                          "table (fresh-start), 0 otherwise",
                          "counter");
        metrics_.counter("yuzu_auth_fresh_start_reset_total");
        if (cfg_.auth_fresh_start_seeded) {
            metrics_.counter("yuzu_auth_fresh_start_reset_total").increment();
        }
        // SCIM v2 provisioning observability (governance hardening round,
        // M-METRICS). Registered unconditionally (like every other describe()
        // in this constructor) even when --scim-enable is off, so Prometheus
        // alert rules can be authored up front; the series simply never
        // increments on a disabled surface.
        metrics_.describe("yuzu_scim_requests_total",
                          "Total /scim/v2/Users and /scim/v2/Groups (#2021) requests, by op "
                          "(create|get|list|replace|patch|delete for Users; "
                          "group_create|group_get|group_list|group_replace|group_patch|"
                          "group_delete for Groups) and status (2xx|4xx|5xx)",
                          "counter");
        metrics_.describe("yuzu_scim_auth_failures_total",
                          "Total /scim/v2/* requests rejected by the bearer gate — a "
                          "credential-guess/replay signal against a surface that can "
                          "provision/deprovision operator accounts",
                          "counter");
        metrics_.describe("yuzu_scim_audit_write_failures_total",
                          "Total SCIM audit rows that failed to persist, by action. Every "
                          "action on this surface, including the three termination actions "
                          "(deactivated/deleted/reactivated), is set-and-proceed: the mutation "
                          "already committed, so a lost audit row does not roll it back. This "
                          "metric is the CC6.8 evidence-integrity alert signal — a sustained "
                          "non-zero rate means the SCIM audit trail has gaps, not that the "
                          "mutation itself failed",
                          "counter");
        metrics_.describe("yuzu_scim_provenance_denied_total",
                          "Total SCIM mutations refused because the target account's "
                          "provisioning_source is not 'scim' (or its role was elevated outside "
                          "SCIM's ownership) — SCIM attempting to touch an account it does not "
                          "own is a misconfigured-IdP or compromised-IdP signal",
                          "counter");
        // SCIM v2 Groups->role application core (#2021). Bumped only when
        // recompute_scim_user_role ACTUALLY changes a role (promotion or
        // demotion via group membership) — never on a no-op recompute, and
        // never for a value that fails the provenance guard (see
        // yuzu_scim_provenance_denied_total for that refusal class, though
        // this particular guard doesn't bump it — recompute_scim_user_role
        // just silently declines).
        metrics_.describe("yuzu_scim_role_changes_total",
                          "Total SCIM-provisioned user role changes applied via SCIM Group "
                          "membership (--scim-admin-group), by the group-membership-driven "
                          "role-recompute core - a sustained rate is a normal signal of IdP "
                          "group-membership churn, not itself an anomaly",
                          "counter");
        // CC6.7 evidence-gap fix (governance hardening round): bumped when
        // recompute_scim_user_role's AuthManager::update_role call reports a
        // genuine AuthDB write failure (row missing/inactive/write error) —
        // a durable role change that could not be applied, distinct from
        // yuzu_scim_role_changes_total's success path.
        metrics_.describe("yuzu_scim_role_change_failures_total",
                          "Total SCIM-driven role changes that failed to write to AuthDB during "
                          "group-membership recompute - a sustained non-zero rate means role "
                          "changes are silently not taking effect",
                          "counter");
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
                          "PK/UNIQUE conflict where the incoming payload MISMATCHES the stored row "
                          "(a forged-id pre-claim #1360, or an agent event_seq_ reset / clock skew "
                          "carrying a different event). Matching-fields redeliveries are NOT counted "
                          "here (see ..._events_redelivered_total). >0 distinguishes 'no drift' from "
                          "'drift silently discarded' (CC7.3 evidence gap #1414).",
                          "counter");
        metrics_.describe("yuzu_server_guardian_events_redelivered_total",
                          "Cumulative idempotent event redeliveries at ingest — a matching-fields "
                          "event_id conflict, i.e. the durable agent lifecycle journal's expected "
                          "at-least-once retry. High is normal after an agent outage/reconnect; this "
                          "is NOT a loss signal (that is ..._events_dropped_total).",
                          "counter");
        metrics_.describe("yuzu_server_guardian_events_ingest_errors_total",
                          "Cumulative OPERATIONAL Guardian ingest faults (a failed BEGIN/prepare/"
                          "insert/commit, or a redelivery compare that could not run). A sustained "
                          "rate means conflicts are going UNCLASSIFIED, so a genuine collision can "
                          "escape ..._events_dropped_total — this is itself alertable (sec-M2). "
                          "Excludes malformed embedded-NUL input (attacker-drivable). Resets on "
                          "server restart.",
                          "counter");
        metrics_.describe(
            yuzu::server::detail::kGuardianEventStoreDurationMetric,
            "Server-side latency of insert_event_classified (the classify+store SQLite operation) "
            "for one Guardian event, split by outcome `status` (inserted|redelivered|conflict|"
            "error). redelivered/conflict run the redelivery byte-compare; inserted does "
            "projection+commit. A validation signal for the off-write-path compare work (#2298) - "
            "NOT the go/no-go (an aggregate histogram can't attribute compare-CPU vs lock-wait; "
            "that needs a concurrent benchmark). Covers the direct-Subscribe and gateway-proxied "
            "paths. Buckets 0.1ms-10s.",
            "histogram");
        // Birth the four status series with the custom ladder ONCE (boundaries fix at first
        // creation) so the hot observe path is a cheap name+label lookup and the series are on
        // /metrics from boot. Mirrors the yuzu_pg_acquire_wait_seconds pattern above.
        // LOAD-BEARING (unhappy-path UP-1): this MUST run in the ServerImpl ctor, before the gRPC
        // listener opens (run() -> BuildAndStart), or the first ingest would default-construct the
        // series with the 5ms-floor buckets and silently lose the sub-ms resolution. Do not move
        // it after the listener starts, and do not switch the observe site to the no-warm-create
        // (default-bucket) path.
        yuzu::server::detail::warm_create_guardian_event_store_metric(metrics_);
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
        // T12 (design doc §7): engine-credential overlap-pair rotation sweep.
        // Deliberately a bounded `reason` label set (currently one value,
        // "successor_unused") and NOT `event="security"` — this is an
        // OPERATIONAL health signal (the module hasn't picked up its new
        // credential yet), distinct from the theft-detection alert channel.
        metrics_.describe("yuzu_engine_principal_rotation_events_total",
                          "Cumulative engine-credential rotation sweep events, by reason "
                          "(bounded label set)",
                          "counter");
        metrics_.describe("yuzu_engine_principal_rotation_auto_revoked_total",
                          "Cumulative engine-credential predecessors auto-revoked at overlap "
                          "window end",
                          "counter");
        // A persistent sweep fault (PG unreachable / audit throw every tick)
        // silently stops predecessor auto-revocation — overlap windows then
        // never close (two live credentials persist). The per-tick try/catch
        // keeps the thread alive; this counter makes that degradation
        // alertable instead of log-only (Gate 8 UP8-6).
        metrics_.describe("yuzu_engine_principal_rotation_sweep_failures_total",
                          "Cumulative engine-credential rotation-sweep ticks that failed with an "
                          "exception (predecessor auto-revocation skipped for that tick)",
                          "counter");
        // #2404: confirm-rotation endpoint outcomes, so a 409-conflict or
        // 503-transient retry storm on confirm is alertable instead of
        // invisible (yuzu_http_requests_total has no per-route label). SCOPE
        // CONTRACT (deliberately narrow, so the label set stays a fact): counts
        // only confirm calls that reached the credential store OR found it
        // unavailable at the store-open guard — NOT pre-store denials
        // (permission / input-validation / MCP approval-gate), which are other
        // families' concern. `result` mirrors the engine_store_error_class
        // taxonomy plus `success`. Operational, NOT event="security" (a replay
        // conflict is an expected agent retry shape, not an attack signal); no
        // principal_id label (bounded cardinality only) — pair with the
        // `engine_principal.credential.confirm` audit rows for per-principal
        // forensics. One describe site only (#2446 last-write-wins on dup).
        metrics_.describe("yuzu_engine_principal_confirm_total",
                          "Engine-credential rotation confirm outcomes by surface (rest|mcp) and "
                          "result (success|conflict|client_error|transient); store-reaching calls "
                          "only, pre-store denials excluded (#2404)",
                          "counter");
        for (auto surface : {"rest", "mcp"}) {
            for (auto result : {"success", "conflict", "client_error", "transient"}) {
                metrics_.counter("yuzu_engine_principal_confirm_total",
                                 {{"surface", surface}, {"result", result}});
            }
        }
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
            // #1830.1: trim leading/trailing ASCII whitespace from the
            // admin-group config value — same trailing-space silent-lockout
            // bug fixed for --saml-admin-group (UP-4, see below). Mutate
            // cfg_ itself (not just the local oidc_cfg copy) so every other
            // reader of cfg_.oidc_admin_group (the /auth/callback route's
            // admin_gid lookup, the startup config-audit line) sees the
            // trimmed value too.
            cfg_.oidc_admin_group = trim_ascii_whitespace(cfg_.oidc_admin_group);

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

        // Initialize SAML 2.0 SP provider if configured.
        // SAML is not supported on Windows (N4 — xmlsec1 is not available on the
        // Windows build): log an ERROR if any SAML flag is set so operators learn
        // immediately that the feature is disabled (fail-closed, never silently half-on).
#ifdef _WIN32
        if (!cfg_.saml_idp_sso_url.empty() || !cfg_.saml_idp_cert.empty() ||
            !cfg_.saml_sp_entity_id.empty() || !cfg_.saml_sp_acs_url.empty()) {
            spdlog::error("SAML is not supported on Windows builds; SAML login disabled"
                          " — fail-closed");
        }
        // saml_provider_ stays null on Windows — routes 404 via is_enabled() check.
#else
        {
            // UP-4: trim leading/trailing ASCII whitespace from the admin-group
            // config value once, here — the single load point where cfg_ is
            // assembled into SamlConfig. Without this, a trailing space in
            // `--saml-admin-group "Admins "` compares raw against the parsed
            // (whitespace-trimmed, see saml_provider.cpp get_text) assertion
            // value and silently never matches — no admin is ever minted, with
            // no error surfaced. group_attribute (the Name to match, not a
            // value) is deliberately NOT trimmed here — IdP attribute names are
            // exact-match XML identifiers, not free-text values susceptible to
            // this class of operator typo. OIDC's admin_group is trimmed the
            // same way, above at OIDC provider init (#1830.1).
            cfg_.saml_admin_group = trim_ascii_whitespace(cfg_.saml_admin_group);

            // sre-S3 / UP-1 / UP-9: half-configured group→role mapping grants
            // no admin and fails silently otherwise — warn at boot so an
            // operator who set one flag but not the other (a likely typo/
            // partial-rollout mistake) finds out before wondering why no SAML
            // login is ever admin. Both-set and both-empty are legitimate
            // configurations and do NOT warn.
            if (cfg_.saml_group_attribute.empty() != cfg_.saml_admin_group.empty()) {
                spdlog::warn("SAML group→role mapping is half-configured "
                             "(--saml-group-attribute=\"{}\", --saml-admin-group=\"{}\") — "
                             "both flags must be set for any SAML login to be promoted to "
                             "admin; as configured, no SAML session will ever grant admin.",
                             cfg_.saml_group_attribute, cfg_.saml_admin_group);
            }

            const bool saml_config_complete = !cfg_.saml_idp_sso_url.empty() &&
                                              !cfg_.saml_idp_cert.empty() &&
                                              !cfg_.saml_sp_entity_id.empty() &&
                                              !cfg_.saml_sp_acs_url.empty() &&
                                              !cfg_.saml_idp_entity_id.empty();
            if (saml_config_complete) {
                // HTTPS gate: SAML ACS is delivered over the browser's back-channel
                // POST.  The __Host-yuzu_saml_bind binding cookie requires Secure
                // attribute (baked into the cookie string) which browsers only send
                // on HTTPS.  Running SAML over plain HTTP would silently strip the
                // binding cookie on every ACS POST, making the CSRF guard inert —
                // effectively leaving the server open to forced-login attacks.
                // Fail-closed: if HTTPS is not enabled, leave saml_provider_ null.
                if (!cfg_.https_enabled) {
                    spdlog::error("SAML requires HTTPS (--https-cert / --https-key must be "
                                  "configured) — SAML login disabled (fail-closed). The "
                                  "browser-binding cookie is Secure-only and would be "
                                  "silently dropped over plain HTTP.");
                } else {
                // Read the IdP signing cert PEM from disk. Fail closed: if the file
                // is unreadable or oversized the provider is not constructed (routes 404).
                // Cap at 64 KiB — a PEM-encoded X.509 cert is at most ~8 KiB; 64 KiB
                // gives generous headroom while preventing a misconfigured path from
                // reading an unbounded file into memory at startup.
                static constexpr std::streamsize kSamlCertMaxBytes = 65536;
                std::ifstream cert_file(cfg_.saml_idp_cert);
                if (!cert_file.is_open()) {
                    spdlog::error("SAML: cannot read IdP cert PEM from '{}' — SAML login"
                                  " disabled (fail-closed)", cfg_.saml_idp_cert);
                } else {
                    // Read one extra byte to detect files that exceed the cap.
                    std::string cert_pem(static_cast<std::size_t>(kSamlCertMaxBytes) + 1, '\0');
                    cert_file.read(cert_pem.data(), kSamlCertMaxBytes + 1);
                    if (!cert_file.eof()) {
                        spdlog::error("SAML: IdP cert PEM '{}' exceeds {} bytes — SAML login"
                                      " disabled (fail-closed)",
                                      cfg_.saml_idp_cert, kSamlCertMaxBytes);
                    } else {
                        cert_pem.resize(static_cast<std::size_t>(cert_file.gcount()));
                        saml::SamlConfig saml_cfg;
                        saml_cfg.idp_entity_id  = cfg_.saml_idp_entity_id;
                        saml_cfg.idp_sso_url    = cfg_.saml_idp_sso_url;
                        saml_cfg.sp_entity_id   = cfg_.saml_sp_entity_id;
                        saml_cfg.sp_acs_url     = cfg_.saml_sp_acs_url;
                        saml_cfg.idp_cert_pem   = std::move(cert_pem);
                        saml_cfg.group_attribute = cfg_.saml_group_attribute;
                        saml_cfg.enabled        = true;
                        // Construct in the single-threaded startup phase — xmlsec global init
                        // is not thread-safe; the std::call_once guard in saml_provider.cpp
                        // makes repeated construction safe thereafter.
                        saml_provider_ = std::make_unique<saml::SamlProvider>(std::move(saml_cfg));
                        if (saml_provider_ && saml_provider_->is_enabled()) {
                            // sre-S2: log the group→role flags alongside the
                            // existing endpoint fields. Both values are
                            // low-sensitivity (an attribute name and a group
                            // identifier, not a secret), so logging them
                            // outright — rather than just a configured/not
                            // boolean — gives an operator a one-line way to
                            // confirm the deployed config matches intent.
                            spdlog::info("SAML SP initialized (idp_sso_url={}, sp_entity_id={}, "
                                         "group_attribute=\"{}\", admin_group=\"{}\")",
                                         cfg_.saml_idp_sso_url, cfg_.saml_sp_entity_id,
                                         cfg_.saml_group_attribute, cfg_.saml_admin_group);
                        } else {
                            spdlog::error("SAML: provider constructed but is_enabled() returned "
                                          "false — SAML login disabled (fail-closed)");
                            saml_provider_.reset();
                        }
                    }
                } // end cert_file.is_open() else
                } // end cfg_.https_enabled else
            } else if (!cfg_.saml_idp_sso_url.empty() || !cfg_.saml_idp_cert.empty() ||
                       !cfg_.saml_sp_entity_id.empty() || !cfg_.saml_sp_acs_url.empty() ||
                       !cfg_.saml_idp_entity_id.empty()) {
                // Partial config — warn so the operator knows which flags are missing.
                spdlog::warn("SAML: incomplete configuration (need --saml-idp-sso-url, "
                             "--saml-idp-cert, --saml-sp-entity-id, --saml-sp-acs-url, "
                             "--saml-idp-entity-id) — SAML login disabled");
            }
        }
#endif

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
            nvd_sync_ = std::make_unique<NvdSyncManager>(
                nvd_db_, cfg_.nvd_api_key, cfg_.nvd_proxy, cfg_.nvd_sync_interval,
                cfg_.nvd_backfill_years);
            // Failure counts are surfaced via SyncStatus and emitted from the /metrics
            // scrape (pull model, #1909) — no sync-thread→metrics_ callback.
            // #1867: do NOT start the background thread here. Its first action is
            // an uncancellable NVD fetch; if a LATER ctor step fails closed (e.g.
            // the Postgres substrate probe below sets startup_failed_), ~ServerImpl
            // would have to join a thread wedged mid-fetch and hang the process
            // forever, defeating any restart policy. The thread is started in run()
            // only after every fail-closed check and the listeners are up.
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
                    // The series is born with the extended 10-60s buckets at metric
                    // registration (#1686), so this hot per-acquire path uses the
                    // cheap name-only lookup — no throwaway bucket-vector alloc per
                    // acquire. (Birth runs at startup, before the pool exists, so the
                    // name-only lookup always resolves to the 60s-bucket series.)
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

        // PreflightRunStore — born-on-PG persistence for /auto runs. CONSTRUCTION
        // is fail-CLOSED per ADR-0012 §1 (a store that cannot migrate/open sets
        // startup_failed_, same as OfflineEndpointStore above): a reachable
        // database whose schema can't be created is a deploy error, not a
        // serve-degraded state. The fail-soft posture is RUNTIME-only (a transient
        // lease timeout degrades /auto to a note; see preflight_run_store.hpp).
        if (pg_pool_ && !startup_failed_) {
            preflight_run_store_ = std::make_unique<PreflightRunStore>(*pg_pool_);
            if (!preflight_run_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: preflight-run store migration/open failed "
                              "(database reachable but the preflight_run_store schema could not be "
                              "created/opened)");
                startup_failed_ = true;
            }
        }

        // DeploymentRunStore — born-on-PG persistence for the /auto DEPLOY stage
        // (the per-device stage→execute state machine). Same fail-CLOSED
        // construction posture as PreflightRunStore (ADR-0012 §1).
        if (pg_pool_ && !startup_failed_) {
            deployment_run_store_ = std::make_unique<DeploymentRunStore>(*pg_pool_);
            if (!deployment_run_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: deployment-run store migration/open failed "
                              "(database reachable but the deployment_run_store schema could not be "
                              "created/opened)");
                startup_failed_ = true;
            }
        }

        // VulnFindingStore — born-on-PG CAVM findings + coverage projection.
        // Same fail-CLOSED construction posture as the run stores (ADR-0012 §1).
        // DORMANT: no matching engine writes to it yet (PR 4).
        if (pg_pool_ && !startup_failed_) {
            vuln_finding_store_ = std::make_unique<VulnFindingStore>(*pg_pool_);
            if (!vuln_finding_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: vuln-finding store migration/open failed "
                              "(database reachable but the vuln_finding_store schema could not be "
                              "created/opened)");
                startup_failed_ = true;
            }
        }

        // AccessReviewStore — born-on-PG campaign persistence for Periodic Access
        // Reviews (SOC 2 CC6.2). Same fail-CLOSED construction posture as the
        // other born-on-PG stores (ADR-0012 §1) — this is compliance evidence, so
        // a reachable database whose schema can't migrate must not serve degraded.
        if (pg_pool_ && !startup_failed_) {
            access_review_store_ = std::make_unique<AccessReviewStore>(*pg_pool_);
            if (!access_review_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: access-review store migration/open failed "
                              "(database reachable but the access_review_store schema could not be "
                              "created/opened)");
                startup_failed_ = true;
            }
        }

        // ApiTokenStore — born-on-PG Bearer-token store (plan PR 4.1). Same
        // fail-CLOSED construction posture as the other born-on-PG stores
        // (ADR-0012 §1): a reachable database whose schema can't migrate/open
        // is a deploy error, not a serve-degraded state. FRESH START — no
        // SQLite backfill; the legacy api-tokens.db is no longer opened.
        if (pg_pool_ && !startup_failed_) {
            api_token_store_ = std::make_unique<ApiTokenStore>(*pg_pool_);
            if (!api_token_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: api-token store migration/open failed "
                              "(database reachable but the api_token_store schema could not be "
                              "created/opened)");
                startup_failed_ = true;
            } else {
                // FRESH-START migration (ADR-0030): the legacy SQLite
                // api-tokens.db is never opened; existing API/MCP tokens are
                // invalidated on upgrade. Warn if the stale file is still on
                // disk so an in-place upgrade's mass 401s are diagnosable (the
                // file is inert + hash-only and can be deleted).
                std::error_code ec;
                const auto legacy_db = cfg_.db_dir() / "api-tokens.db";
                if (std::filesystem::exists(legacy_db, ec)) {
                    spdlog::warn("[auth] Legacy SQLite api-tokens.db found at {} — API/MCP "
                                 "tokens now live in PostgreSQL and any prior tokens were "
                                 "INVALIDATED by the migration (ADR-0030); re-mint them. The "
                                 "old file is inert and can be removed.",
                                 legacy_db.string());
                }
            }
        }

        // EnginePrincipalStore — born-on-PG identity store for autonomous
        // engine principals (plan PR 4.2, design doc §3.1). Same fail-CLOSED
        // construction posture as the other born-on-PG stores (ADR-0012 §1):
        // a reachable database whose schema can't migrate/open is a deploy
        // error, not a serve-degraded state.
        if (pg_pool_ && !startup_failed_) {
            engine_principal_store_ = std::make_unique<EnginePrincipalStore>(*pg_pool_);
            if (!engine_principal_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: engine-principal store migration/open "
                              "failed");
                startup_failed_ = true;
            } else if (api_token_store_ && api_token_store_->is_open()) {
                // Wire the referential-integrity resolver seam (design §6) now
                // that both born-on-PG stores are open. api_token_store_'s
                // create_token engine block fails closed until this is set.
                api_token_store_->set_engine_referent_check(
                    [this](const std::string& id) {
                        // F5 (Hermes pass-2 MEDIUM M3): null-guard in addition to the
                        // declaration-order fix above — belt-and-braces against any future
                        // code path that resets engine_principal_store_ (e.g. a hot-reload)
                        // while this resolver is still installed. Treat "store gone" the
                        // same as "store unreachable": retryable/fail-closed, never a silent
                        // crash or a false Active.
                        //
                        // G9 (governance hardening, cpp-safety SHOULD): this null-check is
                        // sound ONLY under the current lifecycle — engine_principal_store_ is
                        // constructed once above, before the server starts serving requests,
                        // and (per shutdown ordering elsewhere in this file) is only ever
                        // reset to null AFTER the HTTP request-handling threads have drained.
                        // There is today no code path that resets engine_principal_store_
                        // while a request is concurrently in flight, so a bare pointer read
                        // here is race-free. A FUTURE hot-reload feature that swaps or resets
                        // engine_principal_store_ while the server is still live would turn
                        // this into a genuine TOCTOU/use-after-free the null-guard does NOT
                        // cover (reading a non-null pointer here does not guarantee it stays
                        // valid through the get_for_auth() call below). Any such future path
                        // MUST swap the pointer under a mutex or make it a
                        // std::atomic<EnginePrincipalStore*> (or shared_ptr), and MUST add
                        // TSan coverage exercising the reload racing a live lookup — do not
                        // extend the null-guard-only pattern to cover it.
                        return engine_principal_store_
                                   ? engine_principal_store_->get_for_auth(id).status
                                   : EngineLookupStatus::StoreUnreachable;
                    });
            }
        }

        // AuthDB — born-on-PG authentication persistence (ADR-0006 substrate
        // migration). Same fail-CLOSED construction posture as every other
        // born-on-PG store (ADR-0012 §1). Construction order is load-bearing
        // (see the member-declaration comment): FileKeyProvider →
        // SecretCodec (constructed only — NOT init'd yet) → AuthDB (this is
        // what migrates `auth.users` AND registers `mfa_totp_secret` as a
        // secret column) → SecretCodec::init() (runs AFTER AuthDB so the
        // column it validates already exists) → ScimStore.
        if (pg_pool_ && !startup_failed_) {
            const std::filesystem::path key_dir =
                cfg_.ca_dir.empty() ? auth::default_cert_dir() : cfg_.ca_dir;
            auth_key_provider_ = std::make_unique<FileKeyProvider>(key_dir);
            auth_secret_codec_ = std::make_unique<pg::SecretCodec>(*auth_key_provider_);
            auth_db_ = std::make_unique<AuthDB>(*pg_pool_, *auth_secret_codec_);
            if (!auth_db_->is_open()) {
                spdlog::error("[PG] Refusing to start: auth store (AuthDB) migration/open failed "
                              "(database reachable but the auth schema could not be "
                              "created/opened)");
                startup_failed_ = true;
            } else {
                // Substrate-level boot init (ADR-0010 §2) — MUST run before any
                // store attempts an encrypt/decrypt through auth_secret_codec_.
                // AuthDB above is the only registrant on this codec instance
                // today, but init() is where its column is actually verified.
                auto lease = pg_pool_->acquire();
                if (!lease) {
                    spdlog::error("[PG] Refusing to start: could not acquire a connection to run "
                                  "SecretCodec::init() ({})",
                                  pg_pool_->last_error());
                    startup_failed_ = true;
                } else {
                    auto init_res = auth_secret_codec_->init(lease.get());
                    lease.reset();
                    if (!init_res) {
                        spdlog::error(
                            "[PG] Refusing to start: SecretCodec::init() failed — {}: {}",
                            pg::SecretCodec::to_string(init_res.error().kind),
                            init_res.error().message);
                        startup_failed_ = true;
                    } else {
                        auth_mgr_.set_auth_db(auth_db_.get());
                    }
                }
            }
        }

        // ScimStore — born-on-PG SCIM v2 store (ADR-0006). Constructed
        // unconditionally (cheap to open; mirrors every other always-on
        // born-on-PG store) — route registration + the configured bearer
        // token stay gated on --scim-enable in start_web_server(), which
        // reuses this member instead of constructing its own.
        if (pg_pool_ && !startup_failed_) {
            scim_store_ = std::make_unique<ScimStore>(*pg_pool_);
            if (!scim_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: SCIM store migration/open failed "
                              "(database reachable but the scim_store schema could not be "
                              "created/opened)");
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

            // ── ADR-0010 §Decision 3 evidence surface ────────────────────
            //
            // This PR is SecretCodec's FIRST production consumer, and
            // ADR-0010 puts the observability wiring on "the per-store
            // migration PRs" — i.e. here. Without it the codec's KEK
            // lifecycle verbs (`kek.generated`/`kek.rotated`/`kek.retired`)
            // and, most importantly, `secret.decrypt_failure` — the tamper /
            // wrong-KEK / corrupt-blob signal — are computed and then
            // discarded, so a fleet could be failing every MFA decrypt with
            // nothing in the audit log to say so. (Flagged by the 2026-07-25
            // review, HIGH #4: `set_audit_hook` was called only from tests.)
            //
            // Wired HERE rather than at the codec's construction above
            // because `audit_store_` does not exist yet at that point.
            //
            // Lifetime: the lambda captures `this` and reads `audit_store_`
            // at call time rather than capturing the pointer, so a reset
            // store cannot dangle; `stop()` additionally clears the hook
            // before destroying the codec. Attribution is system-level by
            // design (ADR-0010 arch-7) — operator attribution for
            // rotate/retire rides the route-level audit event of whichever
            // surface invoked them.
            if (auth_secret_codec_) {
                auth_secret_codec_->set_audit_hook(
                    [this](std::string_view verb, const std::string& detail_json) {
                        if (!audit_store_ || !audit_store_->is_open())
                            return;
                        const bool failure = (verb == "secret.decrypt_failure");
                        (void)audit_store_->log(
                            {.timestamp = std::time(nullptr),
                             .principal = "system:secret-codec",
                             .principal_role = "system",
                             .action = std::string(verb),
                             .target_type = "Secret",
                             .target_id = "auth",
                             // detail_json carries AAD coordinates, kek_version
                             // and the failure class ONLY — never ciphertext,
                             // plaintext, DEK or key bytes (secret_codec.hpp).
                             .detail = detail_json,
                             .result = failure ? "failure" : "success"});
                    });
            }

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

            // #2530 B5 — mirror the unsigned_packs/unsigned_definitions
            // startup-posture audit pattern: raising --kek-max-live-versions
            // above the shipped default is a deliberate, temporary risk
            // acceptance pending #2525 (no retire route exists, so this is
            // the supported escape hatch that keeps rotation usable once an
            // install hits the ceiling). The matching spdlog::warn fires
            // earlier, in main.cpp, before audit_store_ exists.
            if (detail::kek_ceiling_is_risk_acceptance(cfg_.kek_max_live_versions) &&
                audit_store_ && audit_store_->is_open()) {
                AuditEvent ev;
                ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                ev.principal = "system";
                ev.action = "server.kek_ceiling_raised";
                ev.target_type = "Secret";
                ev.target_id = "kek";
                ev.detail = std::format(
                    "--kek-max-live-versions raised to {} (default {}) at startup — a deliberate, "
                    "temporary risk acceptance pending #2525 (no KEK retire route exists yet)",
                    cfg_.kek_max_live_versions, detail::kKekMaxLiveVersionsDefault);
                ev.result = "success";
                (void)audit_store_->log(ev);
            }

            // #1829 — same startup-posture audit pattern as the two rows
            // above: an SSO admin-group mapping (--oidc-admin-group /
            // --saml-admin-group) is a standing, security-relevant posture
            // that a cold deployment with no logins yet would otherwise
            // leave with zero audit evidence. Emit one row per configured
            // flag so an auditor asking "was group X wired to admin during
            // window Y?" can answer from the audit store. Values here are
            // already trimmed (SAML: UP-4 above; OIDC: #1830.1 at OIDC
            // provider init) and low-sensitivity (a group identifier, not a
            // secret — matches the SAML admin audit-detail precedent,
            // comp-S1/UP-5).
            if (!cfg_.oidc_admin_group.empty() && audit_store_ && audit_store_->is_open()) {
                AuditEvent ev;
                ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                ev.principal = "system";
                ev.action = "config.admin_group_set";
                ev.target_type = "AuthConfig";
                ev.target_id = "oidc";
                ev.detail = "provider=oidc;admin_group=" + cfg_.oidc_admin_group;
                ev.result = "success";
                (void)audit_store_->log(ev);
            }
            if (!cfg_.saml_admin_group.empty() && audit_store_ && audit_store_->is_open()) {
                AuditEvent ev;
                ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                ev.principal = "system";
                ev.action = "config.admin_group_set";
                ev.target_type = "AuthConfig";
                ev.target_id = "saml";
                ev.detail = "provider=saml;admin_group=" + cfg_.saml_admin_group;
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
                                // No rs_store/principal passed here. If this
                                // rule's scope references from_result_set:,
                                // evaluate_scope now ABORTS (nullopt, H1)
                                // rather than silently evaluating the atom
                                // false — value_or({}) then collapses to "not
                                // a member", i.e. the rule is NOT pushed to
                                // this agent. Arming nothing is the safe
                                // direction here; the old comment's "cannot
                                // degrade" claim was wrong for exactly the
                                // NOT-combinator case.
                                for (const auto& id : registry_.evaluate_scope(
                                         *parsed, tag_store_.get(),
                                         custom_properties_store_.get())
                                         .value_or(std::vector<std::string>{}))
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

        // Engine-principal namespace collision-scan preflight (design doc
        // §3.1 upgrade hazard / decision log #3): "the PR 4.2 migration
        // itself scans for pre-existing colliding names rather than allowing
        // silent coexistence". An `engine:`-named local user or RBAC group
        // predating this reservation could otherwise be silently shadowed by
        // (or silently grant roles to) a real engine principal — fail closed
        // and refuse to start rather than let that ambiguity stand. Runs once
        // engine_principal_store_ + rbac_store_ both exist; auth_mgr_.auth_db_ptr()
        // is available from construction.
        if (!startup_failed_ && engine_principal_store_) {
            std::vector<std::string> colliding_users;
            // Symmetric with the groups scan below (governance G3 residual): a
            // users-scan error must fail this preflight CLOSED, not read as
            // "no colliding users" — find_reserved_prefix_users returns nullopt
            // on a scan error vs an empty vector for a completed-clean scan.
            bool users_scan_failed = false;
            if (auto* db = auth_mgr_.auth_db_ptr()) {
                if (auto scan = db->find_reserved_prefix_users("engine:")) {
                    colliding_users = std::move(*scan);
                } else {
                    users_scan_failed = true;
                }
            }
            std::vector<std::string> colliding_groups;
            // G3 (governance hardening, UP-2): `find_local_groups_with_prefix`
            // returns nullopt on a scan error (as opposed to a genuinely empty,
            // successfully-completed scan) — a scan error must fail this
            // preflight closed, not be misread as "no collision found".
            bool groups_scan_failed = false;
            if (rbac_store_) {
                // A non-open store (missing/corrupt/failed-to-load rbac.db)
                // must never be trusted to report a genuine empty scan —
                // treat it exactly like a scan error so this preflight
                // fails closed instead of booting past an unreadable
                // rbac.db (find_local_groups_with_prefix also returns
                // nullopt on !db_, but the explicit is_open() guard here
                // means we never even issue the scan on a store we know is
                // unusable).
                if (!rbac_store_->is_open()) {
                    groups_scan_failed = true;
                } else if (auto scan = rbac_store_->find_local_groups_with_prefix("engine:")) {
                    colliding_groups = std::move(*scan);
                } else {
                    groups_scan_failed = true;
                }
            }
            if (!colliding_users.empty() || !colliding_groups.empty() || users_scan_failed ||
                groups_scan_failed) {
                auto join = [](const std::vector<std::string>& v) {
                    std::string out;
                    for (size_t i = 0; i < v.size(); ++i) {
                        if (i)
                            out += ", ";
                        out += v[i];
                    }
                    return out;
                };
                if (users_scan_failed || groups_scan_failed) {
                    spdlog::error(
                        "[auth] Refusing to start: the 'engine:' namespace collision scan failed "
                        "(users_scan_failed={}, groups_scan_failed={}; see prior error) — cannot "
                        "verify the reserved namespace is clear, failing closed rather than "
                        "booting with an unknown collision state.",
                        users_scan_failed, groups_scan_failed);
                } else {
                    spdlog::error(
                        "[auth] Refusing to start: the 'engine:' namespace is reserved for engine "
                        "principals (design doc §3.3) but pre-existing names collide with it — "
                        "colliding users: [{}]; colliding local RBAC groups: [{}]. Rename or "
                        "remove these before upgrading.",
                        join(colliding_users), join(colliding_groups));
                }
                startup_failed_ = true;
            }
        }
        // Management-group CONFINEMENT hierarchy. Migrated Postgres store
        // (ADR-0006/ADR-0042, schema `management_group_store`) — construction
        // fail-CLOSED per ADR-0012 §1: a reachable database whose schema can't
        // migrate/open is a fatal startup error, never a serve-degraded
        // confinement substrate. `migrate_from_sqlite` runs the one-time,
        // idempotent legacy-`management-groups.db` backfill (ADR-0009) —
        // AUTHORITATIVE confinement scope means a backfill failure is ALSO fatal
        // (never serve on top of partially-migrated confinement config).
        if (pg_pool_ && !startup_failed_) {
            mgmt_group_store_ = std::make_unique<ManagementGroupStore>(*pg_pool_);
            if (!mgmt_group_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: management-group store migration/open failed "
                              "(database reachable but the management_group_store schema could not "
                              "be created/opened)");
                startup_failed_ = true;
            } else {
                mgmt_group_store_->set_metrics(&metrics_);
                auto mgmt_db = cfg_.db_dir() / "management-groups.db";
                if (!mgmt_group_store_->migrate_from_sqlite(mgmt_db)) {
                    spdlog::error("[PG] Refusing to start: management-group legacy-SQLite backfill "
                                  "failed (see prior log lines) — management_group_store is the "
                                  "AUTHORITATIVE confinement substrate and must not serve "
                                  "partially-migrated data. Operator remediation: repair {} or move "
                                  "it aside to skip the backfill (confinement groups in it will NOT "
                                  "carry over)",
                                  mgmt_db.string());
                    startup_failed_ = true;
                }
            }
        }
        if (mgmt_group_store_ && mgmt_group_store_->is_open() && !startup_failed_) {
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
            // store, so a corrupt rbac.db can never widen TAR fleet-scan
            // visibility to the whole fleet.
            mgmt_group_store_->set_rbac_enabled_probe(
                [this]() { return rbac_enforcement_in_effect(rbac_store_.get()); });
            // Ensure root "All Devices" group exists
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
            agent_service_.set_mgmt_group_store(mgmt_group_store_.get());
            if (gateway_service_)
                gateway_service_->set_mgmt_group_store(mgmt_group_store_.get());
        }
        {
            auto quar_db = cfg_.db_dir() / "quarantine.db";
            quarantine_store_ = std::make_unique<QuarantineStore>(quar_db);
        }
        // Scope-walking result sets (capability §30). Migrated Postgres store
        // (ADR-0006/ADR-0036, schema `result_set_store`) — construction fail-CLOSED
        // per ADR-0012 §1 (same template as OfflineEndpointStore above): a
        // reachable database whose schema can't migrate/open is a fatal startup
        // error, never a serve-degraded state. `migrate_from_sqlite` runs the
        // one-time, idempotent legacy-`result_sets.db` backfill (ADR-0009) —
        // AUTHORITATIVE posture means a backfill failure is ALSO fatal (never
        // serve on top of a partially-migrated schema).
        if (pg_pool_ && !startup_failed_) {
            result_set_store_ = std::make_unique<ResultSetStore>(*pg_pool_);
            if (!result_set_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: result-set store migration/open failed "
                              "(database reachable but the result_set_store schema could not be "
                              "created/opened)");
                startup_failed_ = true;
            } else {
                auto rs_db = cfg_.db_dir() / "result_sets.db";
                if (!result_set_store_->migrate_from_sqlite(rs_db)) {
                    spdlog::error("[PG] Refusing to start: result-set legacy-SQLite backfill "
                                  "failed (see prior log lines) — result_set_store is "
                                  "authoritative and must not serve partially-migrated data. "
                                  "Operator remediation: repair {} or move it aside to skip the "
                                  "backfill (pinned sets in it will NOT carry over)",
                                  rs_db.string());
                    startup_failed_ = true;
                } else {
                    spdlog::info("ResultSetStore initialized (schema result_set_store; legacy "
                                 "backfill source {})",
                                 rs_db.string());
                }
            }
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

        // Phase 7: Inventory Store (Issue 7.17) — generic per-source blob store,
        // migrated to Postgres (ADR-0006/0008/0009/0037, schema `inventory_store`).
        // Coexists with the typed SoftwareInventoryStore below (that store's own
        // migration, not this one). Fails closed like every PG store: a reachable
        // database whose schema/backfill cannot complete must not serve degraded.
        if (pg_pool_ && !startup_failed_) {
            inventory_store_ = std::make_unique<InventoryStore>(*pg_pool_);
            if (!inventory_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: generic inventory store migration/open "
                              "failed (database reachable but the inventory_store schema could "
                              "not be created/opened)");
                startup_failed_ = true;
            } else {
                auto inv_db = cfg_.db_dir() / "inventory.db";
                if (!inventory_store_->migrate_from_sqlite(inv_db)) {
                    spdlog::error("[PG] Refusing to start: generic inventory store backfill from "
                                  "legacy {} failed (ADR-0009 fail-closed; see prior log lines). "
                                  "Operator remediation: repair the file or quarantine it as an "
                                  "operator-managed backup per ADR-0037 to skip "
                                  "the backfill — gateway-connected live agents re-push generic "
                                  "blobs on a changed/full report (weekly full floor); direct-"
                                  "connected, offline, and decommissioned agents' "
                                  "generic blobs need manual re-import (ADR-0037)",
                                  inv_db.string());
                    startup_failed_ = true;
                } else {
                    // Set-once before serving (race-free): wires the shared
                    // read-degrade counter + the new ingest-drop/query-truncation
                    // counters (governance IS3).
                    inventory_store_->set_metrics(&metrics_);
                    if (gateway_service_)
                        gateway_service_->set_inventory_store(inventory_store_.get());
                }
            }
        }

        // Typed software-inventory projection — born-on-Postgres (ADR-0016).
        // Coexists with the generic InventoryStore above (the sync-framework
        // baseline). Fails closed like every PG store (ADR-0007/0008): a
        // reachable database whose schema cannot be created/opened must not
        // serve degraded. Wires BOTH server entry points to the typed store.
        if (pg_pool_ && !startup_failed_) {
            software_inventory_store_ = std::make_unique<SoftwareInventoryStore>(*pg_pool_);
            if (!software_inventory_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: software inventory store migration/open "
                              "failed (database reachable but the software_inventory_store schema "
                              "could not be created/opened)");
                startup_failed_ = true;
            } else {
                // Set-once before serving (race-free): wires the read-degrade
                // counter (#1675) + the stale-agents freshness gauge feed.
                software_inventory_store_->set_metrics(&metrics_);
                agent_service_.set_software_inventory_store(software_inventory_store_.get());
                if (gateway_service_)
                    gateway_service_->set_software_inventory_store(software_inventory_store_.get());
                // Catalogue rollup background thread — refreshes the precomputed
                // catalog_rollup/version_rollup the /inventory Software tab reads, so page
                // reads never run the full-table GROUP BY (the data changes only on the
                // daily sync). Hourly, matching the app-perf rollup cadence; runs one
                // refresh on start so the catalogue populates from existing rows at boot.
                // Borrows the store + pool → MUST be stopped before they tear down (in stop()).
                software_catalog_rollup_ = std::make_unique<SoftwareCatalogRollup>(
                    *software_inventory_store_, std::chrono::hours{1}, &metrics_);
                software_catalog_rollup_->start();
            }
        }

        // Typed per-device app-perf daily projection — born-on-Postgres (DEX
        // app-perf-over-time B1). Independent of the software store above (its own
        // schema, its own fail-closed). Wires BOTH server entry points (direct
        // ReportInventory + gateway ProxyInventory) to the typed app_perf seam.
        if (pg_pool_ && !startup_failed_) {
            app_perf_daily_store_ = std::make_unique<AppPerfDailyStore>(*pg_pool_);
            if (!app_perf_daily_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: app_perf daily store migration/open failed "
                              "(database reachable but the app_perf_daily_store schema could not be "
                              "created/opened)");
                startup_failed_ = true;
            } else {
                app_perf_daily_store_->set_metrics(&metrics_);
                agent_service_.set_app_perf_daily_store(app_perf_daily_store_.get());
                if (gateway_service_)
                    gateway_service_->set_app_perf_daily_store(app_perf_daily_store_.get());
            }
        }

        // Typed device-CI projection — born-on-Postgres (ADR-0016 device_ci source).
        // Stable hardware/OS identity (a CMDB CI record), 1:1 per agent. Independent
        // of the stores above (its own schema, its own fail-closed). Wires BOTH server
        // entry points (direct ReportInventory + gateway ProxyInventory).
        if (pg_pool_ && !startup_failed_) {
            device_inventory_store_ = std::make_unique<DeviceInventoryStore>(*pg_pool_);
            if (!device_inventory_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: device inventory store migration/open failed "
                              "(database reachable but the device_inventory_store schema could not "
                              "be created/opened)");
                startup_failed_ = true;
            } else {
                device_inventory_store_->set_metrics(&metrics_);
                agent_service_.set_device_inventory_store(device_inventory_store_.get());
                if (gateway_service_)
                    gateway_service_->set_device_inventory_store(device_inventory_store_.get());
            }
        }

        // Typed detected-licence projection — born-on-Postgres (ADR-0024 Decision
        // 4, SLE `software_licensing` source). Independent of the stores above
        // (its own schema, its own fail-closed). Wires BOTH server entry points
        // (direct ReportInventory + gateway ProxyInventory) to the licensing
        // ingest seam, which is otherwise dead: agent_service_/gateway_service_
        // already carry the set_software_licensing_store() setter + the ingest
        // call, but skip it while the store pointer is null.
        //
        // SLE wiring (PR1a): the detected-licence store (step 7) + the canonical
        // ProductRegistryStore (step 8), both born-on-PG and fail-closed. The
        // entitlement/usage stores, the compliance evaluator, and the posture-rollup
        // thread are the SAM UCE module's (ADR-1005: interpretation is never built
        // in-server) — NOT a later in-server PR step. The /api/v1/sle/* READ routes
        // are registered below (in the route-wiring block) against these two stores.
        if (pg_pool_ && !startup_failed_) {
            software_licensing_store_ = std::make_unique<SoftwareLicensingStore>(*pg_pool_);
            if (!software_licensing_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: software_licensing store migration/open "
                              "failed (database reachable but the software_licensing_store schema "
                              "could not be created/opened)");
                startup_failed_ = true;
            } else {
                software_licensing_store_->set_metrics(&metrics_);
                agent_service_.set_software_licensing_store(software_licensing_store_.get());
                if (gateway_service_)
                    gateway_service_->set_software_licensing_store(software_licensing_store_.get());
            }
        }
        // ProductRegistryStore — SLE canonical product identities + match links
        // (ADR-0024 Decision 4). Sibling of the licensing store: its own schema, its
        // own fail-closed open. The UCE module's compliance evaluator (ADR-1005) is
        // what writes it via the matcher pass; the server constructs it so the store
        // ladder + /readyz probe are complete (roadmap G-10) and the SLE routes can
        // share the pool-guarded lifetime.
        if (pg_pool_ && !startup_failed_) {
            product_registry_store_ = std::make_unique<ProductRegistryStore>(*pg_pool_);
            if (!product_registry_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: product_registry store migration/open "
                              "failed (database reachable but the product_registry_store schema "
                              "could not be created/opened)");
                startup_failed_ = true;
            } else {
                product_registry_store_->set_metrics(&metrics_);
            }
        }

        // Fleet-aggregate app-perf projection (B2) + its roll-up query owner — the
        // long-retention trend substrate, built from B1 by a daily background job.
        // AppPerfFleetStore owns the schema (fail-closed like every PG store);
        // AppPerfRollup is the ADR-0012 cross-store query owner (reads the B1
        // schema, writes the B2 schema, on ONE lease — neither store grows a
        // cross-schema method).
        if (pg_pool_ && !startup_failed_) {
            app_perf_fleet_store_ = std::make_unique<AppPerfFleetStore>(*pg_pool_);
            if (!app_perf_fleet_store_->is_open()) {
                spdlog::error("[PG] Refusing to start: app_perf fleet store migration/open failed "
                              "(database reachable but the app_perf_fleet_store schema could not be "
                              "created/opened)");
                startup_failed_ = true;
            } else {
                app_perf_fleet_store_->set_metrics(&metrics_);
                app_perf_rollup_ = std::make_unique<AppPerfRollup>(*pg_pool_);
                app_perf_rollup_->set_metrics(&metrics_); // rollup-thread liveness signal

                // Group-trend reader (slice 2): on-the-fly B1 aggregate over a
                // management group's members. Borrows the pool, no schema of its
                // own (reads B1's), so no fail-closed gate — it degrades to nullopt.
                app_perf_group_reader_ = std::make_unique<AppPerfGroupReader>(*pg_pool_);
                app_perf_group_reader_->set_metrics(&metrics_);

                // Cohort reader (/auto VERIFY): raw B1 rows for a member set ×
                // app × two versions, agent_id PRESERVED so the compare engine
                // pairs each machine. Borrows the pool, reads B1's schema, no
                // fail-closed gate — degrades to nullopt.
                app_perf_cohort_reader_ = std::make_unique<AppPerfCohortReader>(*pg_pool_);
                app_perf_cohort_reader_->set_metrics(&metrics_);
            }
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
        // ADR-1005 Interim rules (execution-plan PR 1.1): one interceptor on the
        // ONE builder — covers agent, management, and gateway-upstream services
        // and every future RPC method by construction (never a per-method check).
        {
            std::vector<std::unique_ptr<grpc::experimental::ServerInterceptorFactoryInterface>>
                interceptor_factories;
            interceptor_factories.push_back(
                std::make_unique<OnBehalfRejectInterceptorFactory>(&metrics_));
            builder.experimental().SetInterceptorCreators(std::move(interceptor_factories));
        }
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

        spdlog::info("[ADR-1005] on-behalf-of guard active: reserved headers rejected on "
                     "HTTP (excl. health probes) and gRPC ingress; see "
                     "docs/auth-architecture.md");
        spdlog::info("Yuzu Server listening on {} (agents) and {} (management)",
                     cfg_.listen_address, cfg_.management_address);
        if (gateway_service_) {
            spdlog::info("Gateway upstream listening on {}", cfg_.gateway_upstream_address);
        }

        // #1867: start NVD background sync only now — past every fail-closed
        // check and with the listeners up. A construction failure returns above
        // without ever starting the thread, so ~ServerImpl never has to join a
        // thread wedged in an uncancellable fetch.
        if (nvd_sync_) {
            nvd_sync_->start();
        }

        // Create AuthRoutes — must precede start_web_server which uses it
        auth_routes_ = std::make_unique<AuthRoutes>(
            cfg_, auth_mgr_, rbac_store_.get(), api_token_store_.get(), audit_store_.get(),
            mgmt_group_store_.get(), tag_store_.get(), analytics_store_.get(), oidc_mu_,
            oidc_provider_, saml_provider_.get());
        // Nullable setter (design §6) — a null engine_principal_store_ (no PG
        // configured, or its construction failed before startup_failed_ was
        // checked here) makes AuthRoutes::synthesize_token_session fail closed
        // for every engine-kind token rather than dereference a dangling store.
        auth_routes_->set_engine_principal_store(engine_principal_store_.get());

        start_web_server();

        // M/H3 follow-up (2026-07-10 review): start_web_server() can set
        // startup_failed_ (SCIM boot failure) and return before launching
        // the web listener, but by this point the agent/management gRPC
        // listeners are already live (BuildAndStart above). Re-check here,
        // before spinning up any more threads or reaching
        // agent_server_->Wait() below, so a SCIM boot failure genuinely
        // halts the process instead of serving on the gRPC ports with a
        // broken web/SCIM surface. stop() is safe to call this early — every
        // thread/store it joins or resets is joinable()/nullptr-guarded, and
        // it also runs from ~ServerImpl (guarded against double-entry by
        // stop_entered_), so calling it here and letting the destructor run
        // again afterward is a deliberate no-op the second time.
        if (startup_failed_) {
            spdlog::error("run(): refusing to serve — startup failed in start_web_server() "
                         "(SCIM boot failure); stopping the already-started agent/management "
                         "gRPC listeners.");
            stop();
            return;
        }

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
                // Held-open responses across EVERY streaming surface, against the capacity the
                // worker pool was sized for (ADR-0034 Decision 3). This is THE number: it is
                // what says "raise --max-sse-streams", and no per-surface gauge can express
                // it, because the pool is what they all share.
                if (stream_budget_) {
                    metrics_.gauge("yuzu_http_held_open_responses")
                        .set(static_cast<double>(stream_budget_->active()));
                }
                if (pg_pool_) {
                    metrics_.gauge("yuzu_pg_pool_in_use")
                        .set(static_cast<double>(pg_pool_->in_use()));
                    metrics_.gauge("yuzu_pg_pool_open").set(static_cast<double>(pg_pool_->open()));
                    metrics_.gauge("yuzu_pg_pool_size").set(static_cast<double>(pg_pool_->size()));
                    metrics_.gauge("yuzu_pg_pool_waiters")
                        .set(static_cast<double>(pg_pool_->waiters()));
                }
                // Installed-software inventory freshness gauge: agents whose
                // installed_software has not synced within the staleness window
                // (two missed daily cycles — the daily-sync cadence bumps
                // last_seen on every touched/stored sync, so >2 days flags an
                // agent that has stopped syncing, comfortably clear of the
                // per-agent phase-spread + jitter). count_stale_agents bounds BOTH
                // its acquire (250ms) and its execution (per-statement
                // statement_timeout) so it cannot delay the revocation-teardown
                // backstop that shares this serial sweep thread (CH-IN3/UP-2).
                // NOTE: this sweep runs on health_recompute_thread_, which holds a
                // pool lease here — it MUST be join()ed before pg_pool_.reset() in
                // stop() (it is); do not reorder shutdown without preserving that.
                // On a degrade count_stale_agents returns nullopt: hold the gauge
                // at its prior value (no false 0) AND bump a distinct
                // unavailable-counter so a frozen gauge is distinguishable from a
                // genuine low under contention (the 250ms acquire can expire while
                // the 3000ms read budget still clears, so ReadDegraded may stay
                // dormant — sre UP-3).
                if (software_inventory_store_) {
                    // TODO(ADR-0016 source #2): iterate sources instead of
                    // hardcoding installed_software once a second sync source lands
                    // (inventory_state + the {source} gauge label are source-agnostic).
                    constexpr std::int64_t kInventoryStaleWindowSecs = 2 * 24 * 60 * 60;
                    const std::int64_t cutoff =
                        std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count() -
                        kInventoryStaleWindowSecs;
                    if (auto stale = software_inventory_store_->count_stale_agents(cutoff))
                        metrics_.gauge("yuzu_inventory_stale_agents",
                                       {{"source", "installed_software"}})
                            .set(static_cast<double>(*stale));
                    else
                        metrics_.counter("yuzu_inventory_stale_count_unavailable_total").increment();
                }
                // #2530 B7 — KEK cluster-state gauges, sampled HERE rather
                // than from GET /status (a gauge refreshed only on a /status
                // call would go stale and miss a lock held by another server
                // process pointed at the same database — the whole point of
                // a scrape-time collector).
                //
                // #2530 G7-B4: this comment used to claim this sampler
                // mirrored count_stale_agents' degrade handling, but until
                // this fix it only bounded the pool ACQUIRE (250ms) — never
                // EXECUTION — so the KEK reads fell back to the pool's 30s
                // default statement_timeout each. This is a SERIAL thread
                // shared with the security-relevant agent-revocation
                // teardown sweep (and joined before `pg_pool_.reset()` in
                // `stop()`), so a degraded DB could hold it for a long
                // multiple of that. Fixed by wrapping the reads in an
                // explicit transaction with a `SET LOCAL statement_timeout`,
                // matching count_stale_agents' actual pattern (per-statement
                // cap, not just a bounded acquire). Budget: 500ms. Both
                // reads below touch small, cheap relations (`kek_meta` has
                // one row per live KEK version; `pg_locks` is tiny), so a
                // healthy read completes in low single-digit ms — 500ms caps
                // worst-case exposure at ~1s across the two sequential
                // reads, in the same spirit as count_stale_agents' 250ms
                // single-query budget (scaled up slightly for a
                // two-statement transaction), and stays short enough not to
                // meaningfully delay the revocation-teardown backstop
                // sharing this thread.
                //
                // #2530 G7-B4 also DROPS `oldest_kek_version_in_use` from
                // this periodic sweep and retires the
                // `yuzu_server_kek_oldest_version_in_use` gauge with it
                // (docs/user-manual/server-admin.md updated to match): it is
                // the UNBATCHED FULL-COLUMN SCAN whose ceiling #2530
                // explicitly deferred as out of scope (see
                // `test_secret_column_registration_tripwire.cpp`), and
                // running that scan every 15s instead of only on operator
                // demand materially worsens the very problem the deferral
                // acknowledged. `GET /status` still computes it on demand,
                // which is where it belongs.
                //
                // On ANY degrade every gauge below HOLDS its prior published
                // value and `yuzu_server_kek_metrics_unavailable_total` is
                // bumped instead — never a fabricated 0 (it would read as
                // "no KEK versions" / "lock free" during exactly the outage
                // an operator needs this for).
                if (auth_secret_codec_ && pg_pool_) {
                    // In-process, no DB round trip — always fresh.
                    metrics_.gauge("yuzu_server_kek_active_version")
                        .set(static_cast<double>(auth_secret_codec_->active_kek_version()));
                    constexpr auto kKekMetricsAcquireTimeout = std::chrono::milliseconds{250};
                    constexpr auto kKekMetricsStatementTimeout = std::chrono::milliseconds{500};
                    if (auto kek_lease = pg_pool_->try_acquire_for(kKekMetricsAcquireTimeout)) {
                        PGconn* kek_conn = kek_lease.get();
                        pg::PgResult begin{PQexec(kek_conn, "BEGIN")};
                        bool txn_ok = begin.status() == PGRES_COMMAND_OK;
                        if (txn_ok) {
                            const std::string timeout_sql =
                                "SET LOCAL statement_timeout = '" +
                                std::to_string(kKekMetricsStatementTimeout.count()) + "ms'";
                            pg::PgResult t{PQexec(kek_conn, timeout_sql.c_str())};
                            txn_ok = t.status() == PGRES_COMMAND_OK;
                        }
                        if (txn_ok) {
                            // #2530 G8-S2: short-circuit after the FIRST
                            // failed read. A 57014 (statement_timeout) on
                            // `live_kek_version_count` doesn't just fail that
                            // one query — it aborts the whole transaction, so
                            // unconditionally running `kek_op_lock_holder`
                            // next (the pre-fix shape) executed against an
                            // already-aborted transaction: it failed too
                            // (double-counting `..._unavailable_total` for
                            // ONE underlying cause), AND its own
                            // `spdlog::error("KEK op: lock-holder query
                            // failed: ...")` logged a misleading message that
                            // named the wrong query. `read_ok` tracks whether
                            // it is still meaningful to keep reading in this
                            // transaction.
                            bool read_ok = true;
                            if (auto live = auth_secret_codec_->live_kek_version_count(kek_conn))
                                metrics_.gauge("yuzu_server_kek_live_versions")
                                    .set(static_cast<double>(*live));
                            else
                                read_ok = false;

                            // #2530 T5: kek_op_lock_holder distinguishes a
                            // query failure (`determined == false`) from a
                            // genuinely unheld lock — on a failure this gauge
                            // HOLDS its prior published value (the
                            // surrounding block's no-fabricated-zero rule)
                            // rather than publishing a misleading 0. #2530
                            // G7-S1: read `lock_held` directly, never derived
                            // from `pid.has_value()` — a granted holder with
                            // a NULL pid is still held.
                            if (read_ok) {
                                auto holder = detail::kek_op_lock_holder(kek_conn);
                                if (holder.determined) {
                                    metrics_.gauge("yuzu_server_kek_op_lock_held")
                                        .set(holder.lock_held ? 1.0 : 0.0);
                                } else {
                                    read_ok = false;
                                }
                            }

                            if (!read_ok)
                                metrics_.counter("yuzu_server_kek_metrics_unavailable_total")
                                    .increment();

                            // Best-effort: this is a read-only transaction —
                            // a failed COMMIT here (e.g. the connection died
                            // mid-txn, or the transaction was already aborted
                            // by a statement_timeout above) only means the
                            // already-published gauge/counter updates above
                            // stand as read; it does not undo them, and the
                            // connection is returned to the pool either way.
                            pg::PgResult commit{PQexec(kek_conn, "COMMIT")};
                            (void)commit;
                        } else {
                            pg::PgResult rollback{PQexec(kek_conn, "ROLLBACK")};
                            (void)rollback;
                            metrics_.counter("yuzu_server_kek_metrics_unavailable_total")
                                .increment();
                        }
                    } else {
                        metrics_.counter("yuzu_server_kek_metrics_unavailable_total").increment();
                    }
                } else if (!stop_requested_.load(std::memory_order_acquire)) {
                    // #2530 G7-M1: the KEK substrate is unavailable — the
                    // exact condition under which every KEK operation
                    // records outcome="unavailable" below — so say so on the
                    // metrics-unavailable side too, rather than silently
                    // skipping straight past this whole block.
                    //
                    // #2530 G8-S7: gated on `!stop_requested_` — `stop()`
                    // resets `auth_secret_codec_`/`pg_pool_` strictly AFTER
                    // `health_recompute_thread_.join()` returns, so this
                    // branch should never observe null pointers mid-shutdown
                    // today. This check is defense-in-depth against that
                    // ordering ever regressing (e.g. a future teardown
                    // reorder), so a clean shutdown can never arm
                    // YuzuKekMetricsUnavailable on churn elsewhere in this
                    // function.
                    metrics_.counter("yuzu_server_kek_metrics_unavailable_total").increment();
                }

                // #2530 G7-M1: moved OUT of the `auth_secret_codec_ &&
                // pg_pool_` guard above — this loop needs NO Postgres access,
                // it is a pure in-process read of the accumulator each
                // kek_ops.{rotate,rewrap,status} lambda increments at its
                // return points (same pull-model-carried-as-counter pattern
                // as yuzu_server_secret_decrypt_failures_total). That guard
                // is the EXACT condition under which every KEK operation
                // records outcome="unavailable" (the kek_ops.* seams below
                // check the same two pointers and fail with
                // Failure::Unavailable when either is null), so publishing
                // this loop only inside the guard meant the
                // `yuzu_server_kek_operations_total{outcome="unavailable"}`
                // series went dark precisely when that outcome was firing —
                // it needed to be visible, and it was the one thing
                // guaranteed to be invisible.
                {
                    std::lock_guard<std::mutex> kek_outcome_lk{kek_op_outcome_mu_};
                    for (const auto& [key, count] : kek_op_outcome_counts_) {
                        const auto& [op, outcome] = key;
                        metrics_
                            .gauge("yuzu_server_kek_operations_total",
                                   {{"op", op}, {"outcome", outcome}})
                            .set(static_cast<double>(count));
                    }
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
                // #2367: the same observability for the engine-principal
                // revalidation cache. Without these the cache is invisible —
                // its whole job is to keep per-tick stream re-validation off
                // the pool, and there would be no way to see whether it is
                // doing it. `backoff_suppressed` is the brownout signal: it
                // only moves while the store is unreachable AND the per-tick
                // retry amplifier is being held off.
                if (engine_principal_store_) {
                    metrics_.gauge("yuzu_server_engine_revalidate_cache_hits_total")
                        .set(static_cast<double>(engine_principal_store_->revalidate_cache_hits()));
                    metrics_.gauge("yuzu_server_engine_revalidate_cache_misses_total")
                        .set(static_cast<double>(
                            engine_principal_store_->revalidate_cache_misses()));
                    metrics_.gauge("yuzu_server_engine_revalidate_cache_size")
                        .set(static_cast<double>(engine_principal_store_->revalidate_cache_size()));
                    metrics_.gauge("yuzu_server_engine_revalidate_backoff_suppressed_total")
                        .set(static_cast<double>(
                            engine_principal_store_->revalidate_backoff_suppressed()));
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
                    // #2360: retention clock guard. Declined-wipe passes and
                    // failed passes are scraped separately (see describe above).
                    metrics_.gauge("yuzu_server_audit_clock_anomaly_skips_total")
                        .set(static_cast<double>(audit_store_->clock_anomaly_skips_count()));
                    metrics_.gauge("yuzu_server_audit_retention_bootstrap_declines_total")
                        .set(static_cast<double>(audit_store_->bootstrap_declines_count()));
                    metrics_.gauge("yuzu_server_audit_cleanup_failed_total")
                        .set(static_cast<double>(audit_store_->cleanup_failed_count()));
                    metrics_.gauge("yuzu_server_audit_rows_deleted_total")
                        .set(static_cast<double>(audit_store_->rows_deleted_count()));
                    metrics_.gauge("yuzu_server_audit_retention_cap_reached_total")
                        .set(static_cast<double>(audit_store_->cap_reached_count()));
                    metrics_.gauge("yuzu_server_audit_retention_persist_failed_total")
                        .set(static_cast<double>(audit_store_->persist_failed_count()));
                    metrics_.gauge("yuzu_server_audit_retention_passes_total")
                        .set(static_cast<double>(audit_store_->retention_passes_count()));
                    metrics_.gauge("yuzu_server_audit_retention_last_pass_unixtime")
                        .set(static_cast<double>(audit_store_->last_pass_unixtime()));
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
                // 2f PR 3a - the bridge sweep tick: pin-ack teardown, session-
                // death teardown, the kArming age-reaper, and the ring-only
                // pressure hatch all advance here. PAIRED with registry gc ON
                // PURPOSE: the bridge's non-touching exists() classifies a dead
                // session but never destroys its stream, so without this gc() an
                // idle server would hold an expired session's stream (and its
                // pinned finals) until the next client request happened to run
                // one. BOUNDED WORK (governance sre): this shares the
                // security-relevant serial health-recompute budget, so both
                // calls are O(records ≤256) / O(sessions) in-memory scans placed
                // AFTER the CRL/stale-agent sweep (no same-tick delay to it) -
                // microseconds at the 15s cadence, no request-path contention.
                //
                // S-BRIDGE-TICK-GUARD (#2487): this loop is a bare std::thread body,
                // so an exception escaping it is std::terminate - a WHOLE-PROCESS
                // abort triggered by a transient allocation failure inside a
                // maintenance sweep. Both calls allocate (each snapshots its map),
                // and the bridge's teardown path allocates again beneath that.
                //
                // GUARDED SEPARATELY, on purpose: gc() is what actually destroys an
                // expired session's stream and releases its memory, so sharing one
                // try with sweep() would let a snapshot failure under memory
                // pressure skip the call most likely to relieve that pressure. The
                // pairing above is preserved - gc() still runs only alongside a live
                // bridge - but neither failure now suppresses the other. A missed
                // tick simply defers to the next one.
                //
                // The handlers NEST their own observability: spdlog formatting and
                // the metric lookup both allocate, so a flat handler re-throws from
                // inside the very catch meant to contain the failure and terminates
                // anyway (precedent: the nested guard in mcp_stream.cpp's publish
                // boundary). Do not collapse these into a single flat catch.
                if (mcp_stream_bridge_) {
                    try {
                        mcp_stream_bridge_->sweep();
                    } catch (...) {
                        try {
                            spdlog::error("MCP bridge sweep tick failed; deferring to next tick");
                            metrics_
                                .counter("yuzu_mcp_maintenance_tick_failures_total",
                                         {{"tick", "bridge_sweep"}})
                                .increment();
                        } catch (...) {  // NOLINT(bugprone-empty-catch) - nested by design
                        }
                    }
                    if (mcp_sessions_) {
                        try {
                            mcp_sessions_->gc();
                        } catch (...) {
                            try {
                                spdlog::error(
                                    "MCP session gc tick failed; deferring to next tick");
                                metrics_
                                    .counter("yuzu_mcp_maintenance_tick_failures_total",
                                             {{"tick", "session_gc"}})
                                    .increment();
                            } catch (...) {  // NOLINT(bugprone-empty-catch) - nested by design
                            }
                        }
                    }
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
                    metrics_.gauge("yuzu_server_guardian_events_redelivered_total")
                        .set(static_cast<double>(guaranteed_state_store_->events_redelivered_total()));
                    metrics_.gauge("yuzu_server_guardian_events_ingest_errors_total")
                        .set(static_cast<double>(guaranteed_state_store_->events_ingest_errors_total()));
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
                // ADR-0010 §Decision 3 — `yuzu_server_secret_decrypt_failures_total`
                // {store, failure_class}. The codec accumulates these
                // internally; before the 2026-07-25 review (HIGH #4) nothing
                // read them, so the metric existed only as a comment in
                // secret_codec.hpp. Exported pull-model at scrape time (#1909
                // pattern) — the codec keeps the authoritative cumulative
                // count, so this is a `set()` of a monotonic total, not an
                // increment, and a scrape that races a failure simply reports
                // it on the next one.
                if (auth_secret_codec_) {
                    for (const auto& [key, count] : auth_secret_codec_->decrypt_failure_counts()) {
                        const auto& [store, cls] = key;
                        metrics_
                            .gauge("yuzu_server_secret_decrypt_failures_total",
                                   {{"store", store},
                                    {"failure_class",
                                     std::string(pg::SecretCodec::to_string(cls))}})
                            .set(static_cast<double>(count));
                    }
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

        // T12 (design doc §7): engine-credential overlap-pair rotation
        // sweep — auto-revoke + successor-unused warning. Only started when
        // api_token_store_ is actually open (nothing to sweep otherwise).
        // 60s cadence: overlap windows floor at 24h (kOverlapFloorSecs in
        // api_token_store.cpp), so a minute of sweep latency is immaterial
        // to either half's correctness — the sweep is idempotent and a
        // missed tick simply defers to the next one (see
        // sweep_expired_rotations's doc comment).
        if (api_token_store_ && api_token_store_->is_open()) {
            engine_rotation_sweep_thread_ = std::thread([this]() {
                spdlog::info("Engine-credential rotation sweep thread started (interval=60s)");
                // Successor-unused warnings are process-local, best-effort
                // de-duplication (mirrors ApiTokenStore's own rotation-grace
                // cache precedent) — keyed on rotation_group, so the SAME
                // pair isn't re-audited/re-counted every tick while its
                // window is still open. Pruned each tick to whatever
                // list_rotations_nearing_expiry_unused still returns, so a
                // resolved pair (revoked, confirmed, or finally used) frees
                // its slot for a future rotation on the same principal. A
                // process restart forfeits the de-dup state and re-warns
                // once — acceptable for an operational signal.
                std::unordered_set<std::string> warned_rotation_groups;
                // Warn once the predecessor's overlap window has this much
                // time left — matches the 24h overlap floor: the operator
                // gets a full floor-window's notice before auto-revoke, the
                // shortest lead time that is never a false "already gone"
                // read against the shortest window an operator can even set.
                constexpr std::int64_t kSuccessorUnusedWarnLeadSecs = 24 * 3600;

                while (!stop_requested_.load(std::memory_order_acquire)) {
                    for (int i = 0; i < 60 && !stop_requested_.load(std::memory_order_acquire);
                         ++i) {
                        std::this_thread::sleep_for(std::chrono::seconds{1});
                    }
                    if (stop_requested_.load(std::memory_order_acquire))
                        break;
                    // S-SWEEP-EXCEPTION-GUARD: an exception escaping a
                    // std::thread body calls std::terminate (whole-process
                    // crash) — a transient failure here (e.g. an
                    // audit_store_->log throw, bad_alloc) must instead log
                    // and let the loop continue to the next tick
                    // (fail-safe, self-healing; matches the sweep's own
                    // "a missed tick simply defers to the next one" posture).
                    try {
                    if (!api_token_store_ || !api_token_store_->is_open())
                        continue; // defensive — construction-time guard above should hold

                    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                         std::chrono::system_clock::now().time_since_epoch())
                                         .count();

                    // Half 1: auto-revoke elapsed predecessors + clear the
                    // surviving successor's rotation state. A failed tick (pool
                    // contention / query error) is reported via the out-param —
                    // the store swallows it (returns empty) rather than throwing,
                    // so without this the sweep-failures alert would stay at zero
                    // while rotated-out credentials silently outlive their window.
                    bool sweep_tick_failed = false;
                    auto revoked = api_token_store_->sweep_expired_rotations(now, &sweep_tick_failed);
                    if (sweep_tick_failed) {
                        spdlog::warn("Engine-credential rotation sweep tick could not run (pool "
                                     "contention / query failure) — predecessor auto-revoke deferred "
                                     "to the next tick");
                        metrics_.counter("yuzu_engine_principal_rotation_sweep_failures_total")
                            .increment();
                    }
                    for (const auto& predecessor : revoked) {
                        metrics_.counter("yuzu_engine_principal_rotation_auto_revoked_total")
                            .increment();
                        if (audit_store_ && audit_store_->is_open()) {
                            (void)audit_store_->log(
                                {.timestamp = now,
                                 .principal = "system",
                                 .principal_role = "system",
                                 .action = "engine_principal.rotation.auto_revoke",
                                 .target_type = "ApiToken",
                                 .target_id = predecessor.token_id,
                                 .detail = "principal_id=" + predecessor.principal_id +
                                           " reason=overlap_window_elapsed",
                                 .result = "success"});
                        }
                        // Any pair that just resolved no longer needs its
                        // warned-state tracked — the token_id it was keyed
                        // under (rotation_group == successor's token_id,
                        // never the predecessor's) is pruned below anyway,
                        // but drop it here too for clarity/promptness.
                        warned_rotation_groups.erase(predecessor.rotation_group);
                    }

                    // Half 2: successor-unused warning — an OPERATIONAL
                    // health signal (bounded reason label, NOT
                    // event="security"; see the design doc §7 / the
                    // metrics_.describe comment above), kept on its own
                    // channel from any theft-detection alert.
                    auto nearing = api_token_store_->list_rotations_nearing_expiry_unused(
                        now, kSuccessorUnusedWarnLeadSecs);
                    std::unordered_set<std::string> still_nearing;
                    for (const auto& pair : nearing) {
                        still_nearing.insert(pair.successor.rotation_group);
                        if (warned_rotation_groups.contains(pair.successor.rotation_group))
                            continue; // already warned this rotation attempt — don't re-spam
                        warned_rotation_groups.insert(pair.successor.rotation_group);

                        metrics_
                            .counter("yuzu_engine_principal_rotation_events_total",
                                     {{"reason", "successor_unused"}})
                            .increment();
                        if (audit_store_ && audit_store_->is_open()) {
                            (void)audit_store_->log(
                                {.timestamp = now,
                                 .principal = "system",
                                 .principal_role = "system",
                                 .action = "engine_principal.rotation.successor_unused",
                                 .target_type = "ApiToken",
                                 .target_id = pair.successor.token_id,
                                 .detail = "principal_id=" + pair.predecessor.principal_id +
                                           " predecessor_token_id=" + pair.predecessor.token_id +
                                           " overlap_expires_at=" +
                                           std::to_string(pair.predecessor.overlap_expires_at),
                                 .result = "warning"});
                        }
                    }
                    // Prune de-dup entries for pairs that no longer appear
                    // (resolved via revoke, confirm, or the successor
                    // finally being used) so a later rotation on the same
                    // principal can warn again.
                    std::erase_if(warned_rotation_groups, [&](const std::string& group) {
                        return !still_nearing.contains(group);
                    });
                    } catch (const std::exception& e) {
                        spdlog::error("Engine-credential rotation sweep tick failed: {}",
                                     e.what());
                        metrics_.counter("yuzu_engine_principal_rotation_sweep_failures_total")
                            .increment();
                    } catch (...) {
                        spdlog::error("Engine-credential rotation sweep tick failed: unknown "
                                      "exception");
                        metrics_.counter("yuzu_engine_principal_rotation_sweep_failures_total")
                            .increment();
                    }
                }
                spdlog::info("Engine-credential rotation sweep thread stopped");
            });
        }

        agent_server_->Wait();
    }

    /// Decommission an agent for good: fan `delete_agent(agent_id)` across every
    /// per-agent store this server owns, durably erasing the machine's stored
    /// rows (ADR-0024 Decision 11 — the GDPR-erasure path; the per-store
    /// `delete_agent` methods had no production caller before this). Best-effort
    /// in execution, ACCOUNTABLE in result, and null-tolerant: a store that is
    /// not configured (e.g. no Postgres reachable, so every per-agent store —
    /// all born-on-PG — is absent) is skipped, and one store's failure never
    /// aborts the others — but
    /// each `delete_agent` now reports its commit status, so a delete that did
    /// NOT commit is recorded `Failed` (not `Deleted`) and
    /// `DecommissionResult::ok()` confirms erasure across every configured store.
    /// A caller relying on this as Art.17 erasure evidence MUST check `ok()`.
    ///
    /// The cascade is built HERE from the LIVE store pointers on each call
    /// (never a long-lived borrow), so it is inherently safe against the store
    /// teardown ordering in `stop()` — a store already reset to null is simply
    /// skipped.
    ///
    /// PRODUCTION TRIGGER — LIVE: the operator decommission surface that calls this
    /// is `DELETE /api/v1/sle/agents/{id}` (sle_routes.cpp), gated on a SCOPED
    /// CONJUNCTION over every securable the cascade erases through —
    /// `SoftwareLicensing:Delete` AND `Inventory:Delete` AND `GuaranteedState:Delete`
    /// (app_perf_daily is DEX behavioural PII) — plus audit-before-erase fail-closed
    /// (Decision 11). ADDING A STORE BELOW? Add its governing securable's Delete to
    /// that conjunction too; the drift guard in test_agent_decommission.cpp fails
    /// until you do.
    /// Today's OTHER agent-removal paths (registry session teardown, enrollment
    /// deny/remove, cert revocation) are non-durable-data by design and deliberately
    /// do NOT auto-erase (a revoked-for-compromise agent's forensic rows must
    /// survive); this durable erasure is the deliberate, separately-gated Art.17 path.
    [[nodiscard]] DecommissionResult decommission_agent(std::string_view agent_id) {
        AgentDecommission cascade{AgentDecommissionStores{
            .inventory = inventory_store_.get(),
            .software_inventory = software_inventory_store_.get(),
            .app_perf_daily = app_perf_daily_store_.get(),
            .device_inventory = device_inventory_store_.get(),
            .software_licensing = software_licensing_store_.get(),
        }};
        return cascade.decommission(agent_id);
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

        // Signal AuthDB's provisional-MFA reaper to stop up front (it is owned
        // inside AuthDB, not a ServerImpl member thread, so it is not in the
        // joins below). This is signal-only — the join happens at
        // auth_db_.reset() near the pool teardown — but requesting it here lets
        // the reaper wind down concurrently with the rest of shutdown (it polls
        // the flag each 1s), so that later join is near-instant rather than
        // waiting out an in-flight cleanup. Its query is bounded by the pool's
        // statement_timeout/lock_timeout regardless.
        if (auth_db_) {
            auth_db_->request_stop();
        }

        // Join the fleet health recomputation thread
        if (health_recompute_thread_.joinable()) {
            health_recompute_thread_.join();
        }

        // Join the policy evaluation thread (uses policy_evaluator_ + stores,
        // so it must stop before any of them are torn down)
        if (policy_eval_thread_.joinable()) {
            policy_eval_thread_.join();
        }

        // Join the app-perf roll-up thread (borrows app_perf_rollup_ +
        // app_perf_fleet_store_ — must stop before they / the pool are torn down).
        if (app_perf_rollup_thread_.joinable()) {
            app_perf_rollup_thread_.join();
        }
        // Join the pre-flight runner thread (uses preflight_run_store_ +
        // response_store_ + the dispatch path — stop before teardown), then drop
        // the runner so its borrowed pointers can't be ticked again.
        if (preflight_runner_thread_.joinable()) {
            preflight_runner_thread_.join();
        }
        preflight_runner_.reset();

        // Join the schedule tick thread (borrows schedule_engine_ + the
        // instruction/execution/approval/audit stores via schedule_runner_ —
        // must stop before any of them are torn down), then drop the runner
        // so its borrowed pointers can't be ticked again.
        if (schedule_tick_thread_.joinable()) {
            schedule_tick_thread_.join();
        }
        schedule_runner_.reset();

        // Join the result-set maintenance thread (borrows result_set_store_,
        // execution_tracker_, response_store_ — must stop before teardown)
        if (result_set_maint_thread_.joinable()) {
            result_set_maint_thread_.join();
        }

        // Join the insecure-TLS reminder thread (issue #79)
        if (insecure_tls_reminder_thread_.joinable()) {
            insecure_tls_reminder_thread_.join();
        }

        // T12: join the engine-credential rotation sweep thread (borrows
        // api_token_store_ + audit_store_ — must stop before either is torn
        // down; api_token_store_.reset() happens further below alongside
        // engine_principal_store_, per the F5 destruct-before-pool ordering
        // note on those members).
        if (engine_rotation_sweep_thread_.joinable()) {
            engine_rotation_sweep_thread_.join();
        }

        if (schedule_engine_)
            schedule_engine_->stop();
        if (nvd_sync_) {
            if (!nvd_sync_->stop()) {
                // stop() had to detach a wedged sync thread that still references
                // the manager (client_, mu_, cv_, status_, and the NvdDatabase).
                // LEAK the manager so the abandoned thread can't touch freed
                // memory once it wakes — the process is exiting; the OS reclaims
                // it. Destroying it here would be a teardown UAF (#1867).
                (void)nvd_sync_.release();
            }
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

        // 2f PR 3a: the bridge borrows the bus (unsubscribe on teardown) and the
        // session registry - shut it down and release it BEFORE the tracker/bus
        // reset below ([BRIDGE-AFTER-SESSIONS]). shutdown() is idempotent, so
        // the dtor's call becomes a no-op.
        if (mcp_stream_bridge_) {
            mcp_stream_bridge_->shutdown();
            mcp_stream_bridge_.reset();
        }

        // cpp-safety SHOULD (governance hardening round): `auth_mgr_` is
        // owned by main.cpp and OUTLIVES this ServerImpl (unlike every store
        // above, which this object owns) — it holds a raw `AuthDB*` set via
        // set_auth_db() at construction. `auth_db_` destructs along with the
        // rest of this object's members once stop() returns, so a stray
        // post-shutdown call into `auth_mgr_` (host-CLI one-shot, a lingering
        // reference) would otherwise dereference a dangling pointer. Both
        // HTTP and gRPC handler threads are already quiesced by the drains
        // above, so it is safe to null this now — belt-and-braces, same
        // pattern as the tracker/cert-callback nulling just above (the
        // TrackerScope contract, auth_db_'s destruct-before-drop still holds
        // regardless — this only protects the OUTSIDE-owned raw pointer).
        auth_mgr_.set_auth_db(nullptr);

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
        // Generic InventoryStore (ADR-0037): same discipline as the typed PG
        // stores below — null the borrowed pointer in the ingest service
        // that actually borrows it (the gateway ProxyInventory path; the
        // direct ReportInventory path has no generic-store loop and
        // AgentServiceImpl's never-read/never-set pointer was deleted per
        // governance LOW 2026-07-29), then drop the store, BEFORE the pool
        // (governance IS1: this was previously the one PG store missing
        // this unwire-then-reset step).
        if (gateway_service_)
            gateway_service_->set_inventory_store(nullptr);
        inventory_store_.reset();
        // PreflightRunStore borrows pg_pool_ — drop before the pool (the runner
        // thread that leased it is already joined above).
        preflight_run_store_.reset();
        // DeploymentRunStore likewise borrows pg_pool_ — drop before the pool
        // (no background thread in slice 1, but keep the ADR-0012 teardown
        // discipline so a future DeploymentRunner can't UAF).
        deployment_run_store_.reset();
        // VulnFindingStore borrows pg_pool_ — drop before the pool (no background
        // thread this PR; keep the ADR-0012 teardown discipline so a future engine
        // can't UAF).
        vuln_finding_store_.reset();
        // AccessReviewStore borrows pg_pool_ — drop before the pool. No background
        // thread borrows it (only rest_api_v1_/mcp_server_ hold a raw pointer, and
        // every HTTP/MCP handler thread is already quiesced by the drain above);
        // keep the ADR-0012 teardown discipline so a future consumer can't UAF.
        access_review_store_.reset();
        // ApiTokenStore borrows pg_pool_ — drop before the pool. No background
        // thread borrows it (only auth_routes_/settings_routes_/rest_api_v1_
        // hold a raw pointer, and every HTTP handler thread is already
        // quiesced by the drain above); keep the ADR-0012 teardown discipline
        // so a future consumer can't UAF.
        // F5: api_token_store_ MUST reset before engine_principal_store_ — its
        // set_engine_referent_check resolver derefs engine_principal_store_, so
        // dropping api_token_store_ first ensures no lingering resolver can ever
        // observe engine_principal_store_ mid-reset (belt-and-braces alongside
        // the declaration-order fix + the resolver's own null-guard above).
        api_token_store_.reset();
        // EnginePrincipalStore borrows pg_pool_ — drop before the pool, same
        // discipline as api_token_store_ above (ADR-0012 destruct-before-pool).
        engine_principal_store_.reset();
        // Same discipline for the software-inventory store (gov cpp-safety): null the
        // borrowed raw pointers in both ingest services, then drop the store, BEFORE
        // the pool — otherwise the store briefly holds a dangling PgPool& after the
        // pool resets (no UAF today since the gRPC drain has quiesced every ingest
        // handler, but it matches the offline-store contract and is safe if the store
        // ever gains a pool-touching dtor).
        // Stop the catalogue rollup thread (borrows software_inventory_store_ + the pool)
        // BEFORE the store/pool tear down — the dtor signals stop + joins. Idempotent.
        software_catalog_rollup_.reset();
        agent_service_.set_software_inventory_store(nullptr);
        if (gateway_service_)
            gateway_service_->set_software_inventory_store(nullptr);
        software_inventory_store_.reset();
        agent_service_.set_app_perf_daily_store(nullptr);
        if (gateway_service_)
            gateway_service_->set_app_perf_daily_store(nullptr);
        app_perf_group_reader_.reset(); // reads B1; before the daily store + pool
        app_perf_cohort_reader_.reset(); // reads B1; before the daily store + pool
        app_perf_daily_store_.reset();
        // Device-CI store: same discipline — null the borrowed pointers in both ingest
        // services, then drop the store, BEFORE the pool.
        agent_service_.set_device_inventory_store(nullptr);
        if (gateway_service_)
            gateway_service_->set_device_inventory_store(nullptr);
        device_inventory_store_.reset();
        // SLE detected-licence store: same discipline. The decommission cascade
        // is built on-demand from the live store pointers (never a long-lived
        // borrow), so there is nothing else to unwire here before the reset.
        agent_service_.set_software_licensing_store(nullptr);
        if (gateway_service_)
            gateway_service_->set_software_licensing_store(nullptr);
        software_licensing_store_.reset();
        // SLE ProductRegistryStore: the /api/v1/sle/* route closures capture `this`
        // and dereference this store only at request time; the gRPC + HTTP drains
        // above have quiesced every handler, so drop it BEFORE the pool (ADR-0012
        // destruct-before-pool). Nothing borrows it long-lived (its writer is the UCE
        // module's evaluator, out-of-server), so no unwire step precedes the reset.
        product_registry_store_.reset();
        // B2: roll-up (query owner) then the fleet store; both before the pool.
        app_perf_rollup_.reset();
        app_perf_fleet_store_.reset();
        // ManagementGroupStore borrows pg_pool_ (ADR-0042) — null the borrowed
        // raw pointers in the gRPC ingest services, then drop the store, BEFORE
        // the pool. It also holds a `this`-capturing RBAC-enabled probe that
        // reads rbac_store_; dropping the store here disarms that probe well
        // before rbac_store_ tears down. Every HTTP/gRPC handler holding the raw
        // pointer is quiesced by the drains above.
        agent_service_.set_mgmt_group_store(nullptr);
        if (gateway_service_)
            gateway_service_->set_mgmt_group_store(nullptr);
        mgmt_group_store_.reset();
        // ResultSetStore borrows pg_pool_ — drop before the pool. The maintenance
        // thread that leased it is already joined above; every HTTP/gRPC handler
        // holding the raw pointer is quiesced by the drains above.
        result_set_store_.reset();
        // Auth substrate (ADR-0006/0010) — destruct-before-pool, and in
        // dependency order. AuthDB owns a background reaper thread
        // (cleanup_provisional_mfa) that leases pg_pool_ via
        // try_acquire_for(); it is joined only in ~AuthDB::Impl, so auth_db_
        // MUST be reset before pg_pool_ or the reaper's next acquire touches a
        // destroyed pool (UAF on the security-critical auth store — the pure
        // ~ServerImpl order is coincidentally safe via declaration order, but
        // stop() proactively resets pg_pool_ below and would defeat it).
        // auth_db_ borrows auth_secret_codec_, which borrows
        // auth_key_provider_, so tear down inner-to-outer: stores → codec →
        // key provider → pool.
        scim_store_.reset();
        auth_db_.reset();
        // Clear the ADR-0010 audit hook before the codec dies. The hook
        // captures `this` and reads audit_store_ at call time, so it cannot
        // dangle on a reset store — but dropping it here keeps the codec's
        // documented contract ("the wiring must set_audit_hook({}) before
        // destroying the target") satisfied unconditionally.
        if (auth_secret_codec_)
            auth_secret_codec_->set_audit_hook({});
        auth_secret_codec_.reset();
        auth_key_provider_.reset();
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

    // Sanitize an operator-supplied value (definition id, approval id) before
    // it goes into a server log line: control characters — CR/LF especially —
    // would otherwise let a caller forge additional log lines (Gate 8 LOW).
    // Truncates for good measure; callers already substr to bound length.
    static std::string log_safe(const std::string& s, std::size_t max = 64) {
        std::string out;
        out.reserve(std::min(s.size(), max));
        for (std::size_t i = 0; i < s.size() && i < max; ++i) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            out += (c < 0x20 || c == 0x7f) ? '?' : s[i];
        }
        return out;
    }

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
        // Shared with the POST /api/instructions/yaml save path so validate
        // and save can never diverge on what a complete definition is (#1993).
        auto errors = instruction_yaml::validate_definition_yaml(yaml_source);
        // Also run the store-level gates (scope-walking combos, flow-mapping
        // scope) that create/update enforce — same contract, one verdict
        // (governance UP-3). Skip when byte-level errors already fired.
        if (errors.empty()) {
            if (auto err = validate_definition_scope(yaml_source))
                errors.push_back(*err);
        }
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
    //
    // NOTE: a `synthesize_token_session` thin-wrapper used to live here. T8
    // integration (design doc §6/PR 4.2) verified it has zero callers —
    // AuthRoutes' own internal call sites (resolve_session) call
    // `AuthRoutes::synthesize_token_session` directly, not through
    // ServerImpl — so it was deleted rather than widened to the new
    // `std::optional<auth::Session>` return type. If a caller resurfaces,
    // reintroduce it with that signature.

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

    /// #1788: the per-caller Execution:Execute visible set (nullopt == unfiltered),
    /// extracted verbatim from the `/api/command` handler so the MCP dispatch path
    /// (execute_instruction / execute_bundle) can intersect against the SAME
    /// confinement. Composes with — never re-decides — the frozen #1715/INV-7
    /// lattice `RbacStore` already resolves; any store error narrows to "nothing
    /// visible", never "everything" (fail-closed).
    /// Resolve the facts, then hand the DECISION to the one pure composer
    /// (`authz::compose_exec_visible`, authz_model.hpp). This function does
    /// lookups only — it must contain no ordering logic, because the ordering
    /// IS the CDX-001 fix and it belongs somewhere a test can reach without an
    /// RbacStore. It previously lived here, which forced its tests to
    /// re-implement it; the two copies diverged and the precedence ended up
    /// composed by neither.
    yuzu::server::authz::VisibleSet derive_exec_visible(const auth::Session& sess) {
        yuzu::server::authz::ExecVisibleFacts facts;
        facts.service_scoped = !sess.token_scope_service.empty();
        if (facts.service_scoped) {
            if (tag_store_) {
                // B-2b: agents_with_tag_checked distinguishes "genuinely no
                // agents carry this tag" (present, possibly empty) from "the
                // tag DB is degraded" (nullopt on a missing connection or a
                // failed prepare) — the plain agents_with_tag collapsed both
                // to an empty vector, so a degraded read was indistinguishable
                // from a legitimate empty answer.
                // compose_exec_visible's own contract already treats both as
                // deny-all (never unfiltered on a service-scoped token), so
                // the DISPATCH outcome is unchanged; the distinction is what
                // makes a degraded read observable instead of silently
                // indistinguishable from "no agents" at /readyz.
                if (auto svc = tag_store_->agents_with_tag_checked("service",
                                                                   sess.token_scope_service)) {
                    facts.service_tagged = std::unordered_set<std::string>(svc->begin(), svc->end());
                } else {
                    spdlog::error("derive_exec_visible: tag store degraded resolving service "
                                 "scope '{}' — failing closed (deny-all), not open",
                                 sess.token_scope_service);
                    metrics_.counter("yuzu_server_tag_store_degraded_total",
                                     {{"path", "derive_exec_visible"}})
                        .increment();
                    // service_tagged stays nullopt -> compose_exec_visible's
                    // value_or({}) still denies all, same as a present-empty read.
                }
            }
            // tag store absent -> service_tagged stays nullopt -> fail closed.
            return yuzu::server::authz::compose_exec_visible(facts);
        }
        // Legacy-open is RBAC loaded-but-DISABLED. A null / load-failed store is
        // NOT legacy-open (rbac_enforcement_in_effect returns true -> enforce),
        // so a broken store stays fail-closed (BR-002).
        facts.legacy_open = !rbac_enforcement_in_effect(rbac_store_.get());
        facts.elevated = auth::is_elevated(sess);
        facts.global_grant =
            rbac_store_ && rbac_store_->check_permission(sess.username, "Execution", "Execute");
        if (rbac_store_) {
            if (auto v = rbac_store_->visible_agents_for_permission(
                    sess.username, "Execution", "Execute", mgmt_group_store_.get()))
                facts.scoped_visible = std::unordered_set<std::string>(v->begin(), v->end());
            // else: store error -> scoped_visible stays nullopt -> fail closed.
        }
        return yuzu::server::authz::compose_exec_visible(facts);
    }

    /// A-3: the `ConfinedDispatchSink` literal both `dispatch_confined` and
    /// `/api/command` built by hand — byte-identical apart from the local
    /// name (`sink` vs `confined_sink`) — is the same sink because the two
    /// callers dispatch through the SAME registry_. `cmd` is captured by
    /// reference: the returned sink must not outlive it.
    yuzu::server::ConfinedDispatchSink
    make_confined_dispatch_sink(const detail::pb::CommandRequest& cmd) {
        return yuzu::server::ConfinedDispatchSink{
            [this, &cmd](const std::string& aid) { return registry_.send_to(aid, cmd); },
            [this, &cmd] { return registry_.send_to_all(cmd); },
            [this] {
                // all_ids() copies only the ids under the registry lock — NOT
                // to_json_obj()'s full 5-field-per-agent JSON serialisation under
                // the heartbeat/dispatch hot-path mutex (gov perf-S2, the same
                // rationale recorded at the inventory site ~12706). A confined
                // operator broadcasting `__all__` is the enterprise-normal case.
                return registry_.all_ids();
            }};
    }

    /// The SINGLE confined dispatch seam — the one place the target "arm"
    /// (Group / Scope / Ids / Broadcast / None) is resolved and a
    /// `CommandRequest` is handed to `registry_`. Shared by the shared
    /// `command_dispatch_fn` closure (background engines + REST + workflow),
    /// the MCP `execute_instruction`/`execute_bundle` path, and the dashboard
    /// execute closure — so a fifth caller cannot reintroduce an unconfined
    /// copy of the arm logic (CDX-R7-02 / K-R7-02 / #1788).
    ///
    /// EVERY arm intersects the caller's `exec_visible` (nullopt == unfiltered):
    /// a group / scope / id-list / broadcast is a TARGETING mechanism, never an
    /// authz exemption (#1788). `broadcast_on_none` distinguishes callers whose
    /// empty target means "reach nobody, a target was expected" (the shared
    /// closure — `false`, #2500) from those whose UI/tool already normalised an
    /// empty selection into a deliberate fleet broadcast (dashboard + MCP —
    /// `true`). This is the seam #1714/#1715's core chokepoint will EXTEND, not
    /// a per-route copy to be forked.
    /// `principal_role` (C5): carried alongside `principal` on the
    /// scope-evaluation audit rows this seam emits. Defaulted so the four
    /// existing callers (all wired through Deps/DispatchFn shapes owned by
    /// other files — dashboard_routes.hpp, mcp_server.hpp, PolicyEvaluator —
    /// this wave does not touch) keep compiling unchanged and keep emitting
    /// role="" exactly as before; a caller updated in a later wave to thread
    /// its live session's role through can now do so without a second seam.
    ///
    /// CDX-P1-03/K-3 (adv-fix11): attempted widening McpServer::DispatchFn by
    /// one param for exactly this — the session is already in scope at both
    /// MCP call sites (execute_instruction, quarantine_device) via
    /// ExecVisibleFn. Reverted: the typedef is reused verbatim by 18+ fake
    /// DispatchFn lambdas in test_mcp_server.cpp alone (each would need
    /// updating for a signature-only change), plus BundleOrchestrator::
    /// DispatchFn (execute_bundle) is a SEPARATE, REST-shared typedef with no
    /// role concept on its REST side — disproportionate blast radius for an
    /// audit-completeness LOW both external reviewers graded non-blocking.
    /// Still open for a future wave willing to touch those call sites.
    std::pair<std::string, int> dispatch_confined(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id,
        const yuzu::server::authz::VisibleSet& exec_visible,
        bool broadcast_on_none, const std::string& principal_role = {}) {
        // Normalize action to lowercase — agent plugins register actions in
        // lowercase and match case-sensitively (was implicit on the MCP path
        // via upstream lowercasing; a safe superset here).
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

        // Same classifier as the /api/command handler (#2500): an explicit
        // agent_ids list ALWAYS wins over a broadcast request; `__all__` is
        // treated as "no scope expression", never a first-wins broadcast.
        // Computed here (in addition to inside resolve_and_dispatch_confined,
        // which is pure and cheap to call twice) ONLY to decide the
        // None-arm observability below, which is specific to this seam and
        // not something dispatch_confined_arms itself emits.
        const auto arm = classify_dispatch_arm(!agent_ids.empty(), scope_expr);
        if (arm == DispatchArm::None && !broadcast_on_none) {
            // Shared closure: NO TARGET NAMED AT ALL — reach NOBODY, not
            // everybody (#2500). COUNTED, not just logged: this branch is
            // the last line of defence across all callers that dispatch as
            // system, and an unintended fleet-wide dispatch that reports
            // success is the worst failure available. There is no `req`
            // here (background runners call this too), so the counter is
            // the durable signal — no audit row is possible.
            metrics_
                .counter("yuzu_server_dispatch_target_rejected_total",
                         {{"route", "dispatch_closure"},
                          {"reason", std::string(kReasonClosureNoTarget)}})
                .increment();
            spdlog::warn("dispatch {}:{} named no target (no agent_ids, no scope) — reaching "
                         "no agents; pass scope \"{}\" to broadcast deliberately",
                         plugin, norm_action, kBroadcastScope);
        }

        // K-1/QE-2: the ladder resolution + per-arm visible-set intersection
        // (A-3) is the ONE call every caller makes — no per-arm branch is
        // hand-rolled here. The resolvers-and-sink WIRING itself (previously
        // inline here) is extracted to `wire_and_dispatch_confined`
        // (dispatch_scope_ladder.hpp) so it is callable — and testable — with
        // a real AgentRegistry independent of ServerImpl. A parse failure has
        // no `res` to answer on this path (matching pre-existing behaviour):
        // reach nobody, no audit.
        const auto [ignored_command_id, sent] = yuzu::server::wire_and_dispatch_confined(
            registry_, mgmt_group_store_.get(), result_set_store_.get(), tag_store_.get(),
            custom_properties_store_.get(), execution_tracker_.get(),
            [this](const std::string& principal, const std::string& role,
                   const std::string& cmd_id, const std::string& ref) {
                // Governance M1: BINDING owner check — a failing ref aborts
                // dispatch (see the REST raw-dispatch site's comment).
                audit_scope_resolution_failed(principal, role, cmd_id, ref);
            },
            [this](const std::string& principal, const std::string& role,
                   const std::string& cmd_id, const std::string& reason) {
                audit_scope_evaluation_aborted(principal, role, cmd_id, reason);
            },
            command_id, execution_id, principal_role, agent_ids, scope_expr, exec_visible,
            broadcast_on_none, cmd);
        (void)ignored_command_id; // always == command_id, minted above

        forward_gateway_pending();
        if (sent > 0)
            metrics_.counter("yuzu_commands_dispatched_total").increment();
        return {command_id, sent};
    }

    /// #1634: the SINGLE per-agent Response-scope predicate — every Response:Read
    /// fan-out reader routes through this (legacy `/api/responses/*`, the REST
    /// visualization ResponseScopeFn, and the MCP query_responses/aggregate_responses
    /// response_scope_fn) so the posture can never drift between surfaces. Returns
    /// true iff `username` may see `agent_id`'s rows via a management group. A FILTER,
    /// not a gate (writes no response).
    ///
    /// FAILS CLOSED on a corrupt/load-failed rbac.db (#1634 UP-1): gates on
    /// `rbac_enforcement_in_effect`, not raw `!is_rbac_enabled()`. The latter is
    /// fail-OPEN — a corrupt store leaves `db_` null so `is_rbac_enabled()` defaults
    /// false, which would read as "RBAC off → no filter" and re-open the cross-operator
    /// IDOR. `rbac_enforcement_in_effect` returns false (→ legacy-open) ONLY for a
    /// store that is loaded AND explicitly disabled; a null/!is_open() store returns
    /// true (enforce), and `check_scoped_permission` then denies on the dead handle —
    /// so a corrupt rbac.db yields zero rows, never the whole fleet (#1498 ruling).
    bool response_agent_in_scope(const std::string& username, const std::string& agent_id) const {
        if (!rbac_enforcement_in_effect(rbac_store_.get()))
            return true; // loaded & explicitly disabled → legacy-open
        return rbac_store_ && rbac_store_->check_scoped_permission(username, "Response", "Read",
                                                                   agent_id, mgmt_group_store_.get());
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
                // ADR-0042: nullopt (store degraded) → empty visible set
                // (fail-closed: return no agents rather than the full fleet).
                auto visible = mgmt_group_store_->get_visible_agents(username);
                std::set<std::string> visible_set;
                if (visible)
                    visible_set.insert(visible->begin(), visible->end());
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

    // 2026-07-26 hardening round B4: distinct audit + metric for a WHOLE
    // scope evaluation ABORTING (as opposed to audit_scope_resolution_failed's
    // per-ref "not found/not owned" forensic row above). Fires when
    // AgentRegistry::evaluate_scope() returns std::nullopt on a from_result_set:
    // scope — either the membership preload hit a Postgres error
    // (reason="db_degraded", ADR-0036) or a from_result_set: atom had no
    // principal to owner-resolve against (reason="principal_unresolved", B2).
    // Without this, a dispatch silently reduced to 0 targets by an ABORT is
    // indistinguishable in telemetry/audit from a genuine "0 agents matched"
    // (UP-12) — an operator investigating "why did my command reach nobody"
    // would find nothing. The Prometheus counter makes the failure alertable
    // rather than buried in audit.db alone (sre SHOULD).
    void audit_scope_evaluation_aborted(const std::string& principal,
                                        const std::string& principal_role,
                                        const std::string& command_id, const std::string& reason) {
        metrics_.counter("yuzu_scope_eval_degraded_total", {{"reason", reason}}).increment();
        spdlog::warn("scope evaluation aborted: command={} principal={} reason={} — dispatch "
                     "reduced to 0 targets (fail-closed, ADR-0036/B2)",
                     command_id, principal.empty() ? "unknown" : principal, reason);
        if (!audit_store_)
            return;
        AuditEvent ev{};
        ev.timestamp = std::time(nullptr);
        ev.principal = principal.empty() ? "unknown" : principal;
        ev.principal_role = principal_role;
        ev.action = "scope.evaluation_aborted";
        ev.target_type = "result_set";
        ev.target_id = "";
        ev.detail = "SCOPE_EVALUATION_ABORTED command=" + command_id + " reason=" + reason;
        ev.result = "failure";
        if (!audit_store_->log(ev))
            spdlog::error("audit write failed: scope.evaluation_aborted (command={} reason={})",
                          command_id, reason);
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

        // -- Worker pool + held-open-stream budget (ADR-1005 Decision 15(h)) ---
        //
        // Every held-open SSE response pins ONE worker for the life of the stream
        // (the content provider blocks in cv.wait_for). Until now the pool was
        // httplib's implicit default and nothing capped concurrent streams, so a
        // fleet of agentic clients could occupy every worker and starve plain REST.
        //
        // The arrow points FROM the workload TO the pool (ADR-0034). It used to point the
        // other way: the pool was httplib's accidental default (32 threads on an 8-core box)
        // and the stream cap fell out of it at 12 — on a platform whose own design notes size
        // it for "hundreds of agentic clients per server". A cap two orders of magnitude below
        // the workload is not a safety feature, it is a self-inflicted scarcity.
        //
        // A held-open stream costs a BLOCKED thread: ~8-16 KB resident (the 8 MB stack is
        // virtual), zero CPU, one wakeup per heartbeat. Sizing for hundreds is cheap; refusing
        // to serve them is not.
        const std::size_t target_streams = cfg_.max_sse_streams > 0
                                               ? cfg_.max_sse_streams
                                               : detail::kTargetHeldOpenStreamsDefault;
        std::size_t pool_base =
            detail::derive_worker_pool(target_streams, detail::kPlainRestReserveDefault);
        if (cfg_.http_worker_threads > 0) {
            // An operator who pins the pool by hand overrides the derivation — and then the
            // stream target is clamped to what their pool can actually carry, not the reverse.
            pool_base = std::max(cfg_.http_worker_threads, detail::kMinHttpWorkerThreads);
        }
        // Bound the ASK, then create the pool eagerly and in full.
        //
        // Eager is the SAFE direction, and the lazy-growth version of this was worse.
        // httplib's ThreadPool constructor spawns its base count with no try/catch, so a
        // pthread_create failure there unwinds over joinable threads and terminates — but
        // that happens at BOOT, with no traffic, so a host that cannot carry the pool never
        // enters service. Deferring the spawn (base < max) instead activates httplib's
        // dynamic branch, which does `jobs_.push_back(...)` and THEN
        // `dynamic_threads_.emplace_back(std::thread(...))` inside enqueue's lock
        // (httplib.h:9792-9798), called from the accept loop with no handler
        // (httplib.h:11322). The same terminate then becomes reachable at RUNTIME, under
        // load, pre-auth — the server boots healthy and aborts later. Lower probability,
        // far worse blast radius. Note also that a wrapper catching there and returning
        // false is NOT a fix: the job capturing the socket is already queued, so the
        // caller's close_socket() races a worker that will still run it (fd reuse).
        //
        // The real hazard was only ever the SIZE of the ask — `--max-sse-streams 4096`
        // derives 8200 threads — so bound it. 2048 threads affords 1020 streams; a target
        // beyond that is clamped by derive_stream_budget and warned about below, exactly
        // like any other pool the operator's target outruns.
        if (pool_base > detail::kMaxHttpWorkerThreads) {
            spdlog::warn("HTTP worker pool of {} exceeds the {} ceiling; clamping. Concurrent "
                         "held-open streams are clamped to match.",
                         pool_base, detail::kMaxHttpWorkerThreads);
            pool_base = detail::kMaxHttpWorkerThreads;
        }
        const std::size_t pool_max = pool_base; // the pool IS the budget: capacity == pool_max
        web_server_->new_task_queue = [pool_max] {
            // base == max: httplib's dynamic-growth branch stays dead by construction.
            return new httplib::ThreadPool(pool_max, pool_max);
        };
        const std::size_t effective_streams = detail::derive_stream_budget(
            pool_max, detail::kPlainRestReserveDefault, target_streams);
        if (effective_streams < target_streams) {
            spdlog::warn("--max-sse-streams {} exceeds what a pool of {} can carry; clamped to "
                         "{} (plain-REST reserve {}, {} workers per stream for takeover "
                         "handover). Raise --http-worker-threads or lower the target.",
                         target_streams, pool_max, effective_streams,
                         detail::kPlainRestReserveDefault, detail::kMaxProvidersPerStream);
        }
        // #2367: held-open streams and the Postgres pool are coupled capacities,
        // and nothing else says so at boot. Every live stream re-validates its
        // credential each pump tick against this pool. Those reads are cached,
        // so steady state is O(streams / TTL) rather than O(streams x tick) —
        // but the refreshes still land here alongside ordinary request traffic,
        // and a stream capacity far above the pool size is the shape that turns
        // a pool blip into a correlated stall.
        //
        // Deliberately warned on the EFFECTIVE capacity, not the configured
        // target: a hand-pinned --http-worker-threads can clamp the target well
        // below what was asked for, and warning about capacity the server will
        // never admit is just noise.
        //
        // Advisory only — not a clamp and not a startup failure. The safe ratio
        // depends on link latency and traffic mix, so this points at the metrics
        // that answer it rather than inventing a rule. The threshold sits above
        // the shipped default ratio (128 streams / 16 connections = 8:1, so a
        // default server is quiet) and below the cliff #2367 names (512 on a
        // pool of 16 = 32:1).
        if (pg_pool_) {
            constexpr std::size_t kStreamsPerPgConnAdvisory = 16;
            if (effective_streams > pg_pool_->size() * kStreamsPerPgConnAdvisory) {
                spdlog::warn(
                    "[PG] effective SSE stream capacity {} is more than {}x --postgres-pool-size "
                    "{}. Held-open streams re-validate their credential against this pool, so at "
                    "this ratio a pool brownout can stall streams and ordinary requests together. "
                    "Watch yuzu_pg_acquire_wait_seconds and yuzu_pg_pool_in_use; if they climb, "
                    "lower the stream capacity or raise --postgres-pool-size (and check the "
                    "database can carry the extra connections — enlarging the pool against an "
                    "already-struggling server makes things worse, not better). Engine-principal "
                    "streams are the heaviest case; other SSE surfaces re-validate more cheaply.",
                    effective_streams, kStreamsPerPgConnAdvisory, pg_pool_->size());
            }
        }
        stream_budget_ =
            std::make_unique<detail::StreamBudget>(detail::StreamBudget::Config{effective_streams});
        metrics_.gauge("yuzu_http_held_open_capacity")
            .set(static_cast<double>(effective_streams));
        // Described at startup but never set, so the series existed in metadata tooling
        // and never in /metrics — worse than absent, because the describe() text sells it
        // as the answer to "why am I being rejected below my configured cap". Set beside
        // its sibling above, from the same post-clamp number.
        metrics_.gauge("yuzu_mcp_streams_cap").set(static_cast<double>(effective_streams));
        metrics_.gauge("yuzu_http_worker_pool_size").set(static_cast<double>(pool_max));
        spdlog::info("HTTP worker pool: {} threads, sized for {} concurrent held-open responses "
                     "(plain-REST reserve {}). EVERY streaming surface leases from one budget: "
                     "GET /mcp/v1/, GET /api/v1/events, the dashboard executions drawer, and the "
                     "legacy /events stream. Watch yuzu_http_held_open_responses / "
                     "yuzu_http_held_open_capacity; the ceiling is thread-count (ADR-0034).",
                     pool_max, effective_streams, detail::kPlainRestReserveDefault);

        // -- Auth middleware (pre-routing) -----------------------------------
        web_server_->set_pre_routing_handler([this](const httplib::Request& req,
                                                    httplib::Response& res)
                                                 -> httplib::Server::HandlerResponse {
            // Per-principal quota (PR 4.4) — defensive reset at the TOP of
            // pre-routing. httplib's worker-thread affinity means a QuotaSlot
            // stashed in tls_quota_slot() on this thread by a PRIOR request is
            // normally released either by that request's post-routing handler
            // (non-streaming) or by its stream's own resource-releaser via
            // adopt_quota_slot_into_stream (streaming, UP-1) before this
            // thread is handed a new one; this reset reclaims a slot leaked by
            // any prior request that bypassed BOTH — the only such bypass
            // today would be a future WebSocket upgrade (httplib DOES support
            // WebSocket; this codebase just registers no handler for one
            // today — the real safety is the absence of a handler, not a
            // protocol limitation). See detail::tls_quota_slot()'s doc
            // comment.
            detail::tls_quota_slot().reset();

            // principal_class metric (PR 4.5) — defensive reset at the TOP of
            // pre-routing, before all early returns, mirroring the quota
            // slot reset immediately above. Set true further down, right
            // after session resolution, when the RESOLVED session is an
            // engine principal; read at the post-routing metric emission.
            // The PRIMARY clear is the post-routing handler's
            // EngineClassStashClear scope guard, which fires on every exit
            // from that lambda (incl. throw) — including the requests
            // httplib rejects BEFORE pre-routing ever runs (malformed
            // request line, URI too long, bad Range), which never reach
            // this reset. This one is defense-in-depth for requests that
            // DO make it through pre-routing. See principal_class.hpp's
            // detail::tls_engine_principal() doc comment for the full
            // contract.
            detail::tls_engine_principal() = false;

            // Lightweight probes — always allowed, no auth, no rate limit.
            // /health and /api/health are included here (governance Gate 7,
            // unhappy-path UP-1) so monitoring integrations behind a NAT or
            // sharing a source-IP bucket with authed REST traffic cannot
            // 429-starve the health probe. The endpoints themselves are
            // strictly read-only and documented as unauthenticated.
            // Liveness/readiness probes are EXEMPT from the on-behalf-of guard
            // below — a RECORDED ADR-1005 exception (documented in
            // docs/auth-architecture.md; ledger entry lands with the ADR).
            // Governance Gate 5 (CH-3/UP-5): a mesh/SSO proxy that stamps a
            // reserved header on every request must not be able to 403 the
            // probes and crash-loop the pod — a probe performs no
            // identity-bearing action, nothing consumes the header on this
            // path, and a bricked orchestrator hides the misconfiguration the
            // guard exists to surface. Every other path rejects below.
            if (req.path == "/livez" || req.path == "/readyz" || req.path == "/health" ||
                req.path == "/api/health") {
                return httplib::Server::HandlerResponse::Unhandled;
            }

            // ADR-1005 Interim rules (execution-plan PR 1.1): the server accepts
            // NO on-behalf-of assertion on any surface until server-verifiable
            // delegation ships (Phase 5) — and client-asserted delegation stays
            // rejected permanently even then. Reject (not ignore) before auth,
            // the unauthenticated allowlist, and the rate limiter, so REST, MCP
            // (same httplib instance), fragments, and static all reject; the four
            // probe paths above are the single recorded exception.
            // Pre-limiter placement means a reserved-header flood gets per-request
            // 403s, not 429s — the scan is cheaper than the limiter lookup, and
            // the warn is throttled in note_rejection so the flood can't fill the
            // disk; the counter records every event. Log lines carry the CANONICAL
            // reserved spelling plus sanitized method/path (httplib percent-decodes
            // req.path, so raw control chars would otherwise forge security-log
            // lines). Reserved names + rationale: on_behalf_guard.hpp; the agent
            // gRPC channel gets the same guard via grpc_on_behalf_interceptor.hpp.
            if (auto reserved = onbehalf::find_reserved_key(req.headers)) {
                if (onbehalf::note_rejection(metrics_, "http")) {
                    spdlog::warn(
                        "[ADR-1005] rejected {} {} carrying reserved on-behalf-of "
                        "header '{}' from {} (1 log per {} rejections; counter "
                        "records all)",
                        onbehalf::sanitize_for_log(req.method, 16),
                        onbehalf::sanitize_for_log(req.path), *reserved,
                        onbehalf::sanitize_for_log(req.remote_addr, 64),
                        onbehalf::kLogEvery);
                }
                res.status = 403;
                res.set_content(
                    detail::a4_denial(
                        res, 403,
                        "on-behalf-of assertions are not accepted on any surface (ADR-1005); "
                        "remove the reserved header",
                        detail::A4ErrorOpts{
                            .remediation = "remove the reserved header; see "
                                           "docs/auth-architecture.md 'On-behalf-of "
                                           "assertions rejected' (ADR-1005)"}),
                    "application/json");
                return httplib::Server::HandlerResponse::Handled;
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
            // SAML 2.0 SSO start (GET /auth/saml/start) is the auth-flow entry
            // point: flooding it fills pending_requests_ (cap 1000, oldest
            // evicted), which lets an attacker evict legitimate users' in-flight
            // login requests.  Apply the tighter login bucket — same reasoning
            // as POST /login (H-C, Hermes round-2 2026-07-01).
            // POST /saml/acs is also an auth-completion endpoint; include it
            // for consistency so a flood of fake assertions is rate-limited too.
            bool is_login = (req.path == "/login" || req.path == "/login/mfa" ||
                             req.path == "/login/mfa/stepup" ||
                             req.path == "/login/mfa/enroll") &&
                            req.method == "POST";
            is_login = is_login ||
                       (req.path == "/auth/saml/start" && req.method == "GET") ||
                       (req.path == "/saml/acs"        && req.method == "POST");
            auto& limiter = is_login ? login_rate_limiter_ : api_rate_limiter_;
            if (!limiter.allow(req.remote_addr)) {
                res.status = 429;
                res.set_header("Retry-After", "1");
                res.set_content(
                    R"({"error":{"code":429,"message":"rate limit exceeded"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }

            // MCP request-body bound (#2437). Placed HERE, after the rate
            // limiter and before auth, for two reasons that are easy to get
            // wrong:
            //   * httplib calls this pre-routing handler BEFORE it reads the
            //     request body (httplib.h: pre_routing_handler_ in routing(),
            //     read_content later in the same function), so returning
            //     Handled costs a header parse and never buffers the payload.
            //     Enforcing the same bound inside the MCP handler would be too
            //     late — the body is already in memory by then.
            //   * it is per-path, NOT the server-global
            //     `set_payload_max_length` knob, which would also cap the
            //     multipart certificate upload and content distribution on
            //     this same httplib instance. httplib's 100 MB default stays
            //     as the outer backstop for every other route.
            // Unlike the on-behalf-of guard above, this sits AFTER the rate
            // limiter: there is no diagnostic reason to let an oversized-body
            // flood bypass the limiter, and no misconfiguration it would mask.
            // A chunked or Content-Length-less POST/PUT/PATCH is REFUSED 411,
            // not admitted: httplib consults Transfer-Encoding before
            // Content-Length and reads a header-less POST to EOF, so either
            // shape would revert to the 100 MB default and evade this cap
            // entirely. A bound removable by deleting a header is not a bound.
            // ON THE UNREAD BODY (checked at primary source against the
            // vendored httplib 0.37.1 — don't re-derive, and re-check on a
            // vcpkg baseline bump). Returning Handled means the body is never
            // read off the socket. What ACTUALLY happens next:
            //   * write_response_core stamps `Connection: close` on any status
            //     >= 400 (httplib.h:10789, "Don't leave connections open after
            //     errors"), so a conforming client closes.
            //   * but NOTHING sets httplib's `connection_closed` flag for an
            //     error response, so process_server_socket_core loops again
            //     (httplib.h:5516-5531). A client that already transmitted the
            //     declared body — which it always has under
            //     `Expect: 100-continue`, since process_request auto-answers
            //     100 BEFORE routing — leaves those bytes to be parsed as
            //     subsequent request lines on this same socket.
            //   * bounded: <= keep_alive_max_count_ (100) parses and the idle
            //     timeout, then teardown. Malformed lines 400 before
            //     pre-routing runs (so they skip the rate limiter); a
            //     well-formed smuggled request goes through the FULL middleware
            //     chain including auth, so there is no auth bypass.
            // Same shape as the two early returns above (on-behalf-of 403,
            // rate-limit 429), which have always returned Handled on POSTs
            // carrying bodies — this adds an instance of an existing pattern,
            // not a new one.
            // CAVEAT IF A REVERSE PROXY IS EVER PUT IN FRONT: an unread
            // Content-Length body is a textbook request-smuggling primitive
            // between proxy and origin. The shipped rigs expose the server
            // directly, so this is a documented constraint, not a live bug.
            // The DECISION lives in web_utils.hpp so it has direct unit
            // coverage (same reason is_login_exempt_path was extracted from
            // this lambda); only this call site is review-only.
            // The path test is hoisted to the CALL SITE, not left inside the
            // predicate: get_header_value_u64 is a function ARGUMENT and is
            // therefore evaluated unconditionally, so the predicate's internal
            // && cannot short-circuit it. Measured at 14.22 ns/request
            // unguarded vs 0.84 ns guarded, on EVERY request server-wide
            // (governance perf-S1).
            if (is_mcp_path(req.path)) {
              // Hoisted ABOVE the try so the catch below can answer with the
              // right status: collapsing an unmeasurable-body refusal into a
              // 413 would tell the client to shrink a body whose size was
              // never the problem.
              bool unmeasurable_cause = false;
              // CONTAIN THE WHOLE BRANCH, not just the metric (governance Gate 8,
              // security + cpp-safety). httplib invokes this handler from TWO
              // sites: routing() (inside process_request's try/catch) and the
              // WebSocket-upgrade path at httplib.h:11741, which is NOT — and
              // ThreadPool::worker runs tasks bare. A GET /mcp/v1/ carrying
              // `Upgrade: websocket` and an oversized Content-Length reaches
              // here via that second site, so a bad_alloc from the header read,
              // the log, the sanitizers, the counter OR the envelope build is
              // std::terminate. The first attempt guarded only the one operation
              // it had been told about; the hazard is the path.
              try {
                const bool oversize = mcp_body_exceeds_cap(
                    req.path, req.get_header_value_u64("Content-Length", 0),
                    mcp::kMcpMaxRequestBodyBytes);
                // Header VALUES passed through, not a re-implementation of
                // httplib's parsing — matching its decision by hand is what
                // let `Transfer-Encoding: Chunked` through last round.
                const bool unmeasurable = mcp_body_unmeasurable(
                    req.path, req.method, req.has_header("Content-Length"),
                    req.get_header_value("Transfer-Encoding"),
                    req.get_header_value("Content-Encoding"));
                unmeasurable_cause = unmeasurable;
                if (oversize || unmeasurable) {
                    // Throttled log: this is a pre-auth ingress rejection with
                    // NO principal to audit, and observability-conventions.md
                    // requires metric + sampled log for exactly that shape.
                    // Mirrors the on-behalf-of guard above, whose sanitizer
                    // this reuses (httplib percent-decodes req.path, so raw
                    // control bytes would otherwise forge log lines).
                    // OWN throttle, NOT onbehalf::note_rejection (governance
                    // Gate 8 security HIGH-1). Reusing it fed
                    // yuzu_onbehalf_rejected_total, which carries a CRITICAL
                    // alert reading "likely a header-injecting proxy" — so an
                    // unauthenticated chunked-POST flood would have paged
                    // someone about an ADR-1005 breach that never happened,
                    // and would have consumed the shared 1-in-100 log slot
                    // that the genuine on-behalf-of warnings need. Never
                    // borrow a security control's counter for a transport
                    // bound.
                    // ONE COUNTER PER REASON. A shared counter lets a cheap
                    // over_cap flood (huge Content-Length, no body sent)
                    // suppress ~99% of the unmeasurable lines, hiding the
                    // rarer signal behind the noisier one.
                    static std::atomic<std::uint64_t> over_cap_hits{0};
                    static std::atomic<std::uint64_t> unmeasurable_hits{0};
                    constexpr std::uint64_t kBodyLogEvery = 100;
                    auto& hits = unmeasurable ? unmeasurable_hits : over_cap_hits;
                    if (hits.fetch_add(1, std::memory_order_relaxed) % kBodyLogEvery == 0) {
                        spdlog::warn("[#2437] rejected {} {} from {}: {} (1 log per {} "
                                     "rejections; the counter records all)",
                                     onbehalf::sanitize_for_log(req.method, 16),
                                     onbehalf::sanitize_for_log(req.path),
                                     onbehalf::sanitize_for_log(req.remote_addr, 64),
                                     unmeasurable ? "unmeasurable body" : "body over cap",
                                     kBodyLogEvery);
                    }
                    try {
                        metrics_
                            .counter("yuzu_mcp_body_too_large_total",
                                     {{"reason", unmeasurable ? "unmeasurable" : "over_cap"}})
                            .increment();
                    } catch (...) { // NOLINT(bugprone-empty-catch)
                        // Guarded because this call site is NOT inside
                        // httplib's try/catch on the WebSocket-upgrade path
                        // (httplib.h:11741 vs routing()'s at :11811), and
                        // ThreadPool::worker invokes tasks bare — an escaped
                        // throw here is std::terminate (cpp-safety S1 / UP-9).
                        // The sibling handler-side increment is guarded the
                        // same way; observability must never kill the process.
                    }
                    res.status = unmeasurable ? 411 : 413;
                    res.set_content(
                        unmeasurable
                            ? detail::a4_denial(
                                  res, 411,
                                  "MCP requests must carry a body this server can size "
                                  "in advance",
                                  detail::A4ErrorOpts{
                                      .remediation =
                                          "send the JSON-RPC body with a Content-Length "
                                          "header, no Transfer-Encoding, and no "
                                          "Content-Encoding other than identity; a body "
                                          "whose size cannot be checked before reading it "
                                          "cannot be admitted under the 4 MiB MCP cap "
                                          "(see docs/mcp-server.md)"})
                            : detail::a4_denial(
                                  res, 413, "request body exceeds the MCP transport limit",
                                  detail::A4ErrorOpts{
                                      .remediation =
                                          "the largest accepted MCP request body is 4 MiB; "
                                          "reduce the arguments, or for a large "
                                          "execute_bundle use the REST twin POST "
                                          "/api/v1/bundles (see docs/mcp-server.md)"}),
                        "application/json");
                  return httplib::Server::HandlerResponse::Handled;
                }
              } catch (...) { // NOLINT(bugprone-empty-catch)
                  // Last-resort containment for the WHOLE branch, including the
                  // header read that decides it. We cannot build an envelope if
                  // we got here, but we can still refuse rather than let the
                  // throw reach httplib's UNGUARDED WebSocket-upgrade call site
                  // and take the process down.
                  res.status = unmeasurable_cause ? 411 : 413;
                  return httplib::Server::HandlerResponse::Handled;
              }
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
            // SAML 2.0 auth-flow routes are pre-session by design (identical
            // rationale to /auth/oidc/start + /auth/callback).  Without these
            // exemptions, a non-authenticated user trying to start SSO would be
            // redirected to /login before the SAML flow handler runs.
            // The exact exempt-path decision lives in `is_login_exempt_path`
            // (web_utils.hpp) so it has direct unit coverage (H1, 2026-07-08
            // SCIM review) — this call site runs AFTER the rate limiter
            // above, so rate-limiting stays in effect for every exempt path.
            if (is_login_exempt_path(req.path)) {
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

            // principal_class metric (PR 4.5) — stash whether this RESOLVED
            // session is an engine principal, for the post-routing metric
            // emission (principal_class.hpp's principal_class_resolved).
            // INDEPENDENT of the quota-gate outcome below: a 429'd engine
            // request still classifies as "engine" — the traffic shape was
            // still engine-shaped even though it got rejected. Session::is_engine()
            // is the canonical predicate, mirroring the sibling belts in
            // principal_quota_gate.hpp's apply_engine_quota_gate (also
            // mcp_server.cpp's deny_if_engine_session / rest_api_v1.cpp's
            // deny_engine_session) so a future engine auth path can't
            // silently miss one copy.
            detail::tls_engine_principal() = session->is_engine();

            // Per-principal quota cap (PR 4.4, ADR-1005 class engine
            // principals) — THE single pre-routing chokepoint gate (#2225
            // ADR-0017); no separate route, no bypass. Runs AFTER session
            // resolution so we have a stable principal id. The security
            // DECISION (principal_kind/auth_source == "engine" two-predicate
            // check (S1), mcp-vs-rest render pick, UP-1 always-try_acquire)
            // lives in the pure, testable detail::apply_engine_quota_gate —
            // this is a thin caller that only owns the httplib-specific,
            // worker-thread-affine slot stash (R2, see
            // detail::tls_quota_slot()'s doc comment) and the
            // Handled/Unhandled return. The gate mints its own correlation
            // id lazily, only on the reject path — no cid is computed here.
            {
                bool rejected = false;
                // "engine:<slug>" for an engine session — the STABLE
                // authorization principal (see Session::username's doc
                // comment); never display_name. auth_source is the second
                // S1 predicate (see apply_engine_quota_gate's doc comment).
                // Both ignored by the gate for a non-engine session.
                auto slot = detail::apply_engine_quota_gate(session->principal_kind,
                                                             session->auth_source,
                                                             session->username, req, res,
                                                             principal_quota_, metrics_,
                                                             rejected);
                if (rejected) {
                    return httplib::Server::HandlerResponse::Handled;
                }
                if (slot) {
                    // UP-1: this slot is now held regardless of whether the
                    // route is streaming. A streaming route is expected to
                    // `adopt_quota_slot_into_stream` it out of here before
                    // post-routing's reset (below) fires; a normal route
                    // leaves it here and post-routing releases it.
                    detail::tls_quota_slot() = std::move(*slot);
                }
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
            // principal_class metric (PR 4.5) — clear the engine-class stash on EVERY
            // exit from this handler, via a guard whose destructor runs AFTER the
            // metric emission below (never clears before the read — cf. the reset
            // ordering) AND even if that emission throws. Load-bearing, not just
            // hygiene: httplib runs post-routing for requests it rejects BEFORE
            // pre-routing (malformed request line->400, URI>8K->414, bad Range->416;
            // httplib.h write_response_core), which never hit the top-of-pre-routing
            // reset — so a leaked `true` from a post-routing throw would mislabel the
            // next such parse-error response on the same keep-alive worker as
            // "engine". (governance unhappy-path F1/F2.)
            //
            // ORDERING IS LOAD-BEARING: this guard MUST remain the FIRST local
            // declared in this lambda. C++ destroys locals in reverse
            // construction order, so being declared first makes it destruct
            // LAST — after the metric emission reads the stash below. Declaring
            // any local before it would move its destructor ahead of the read
            // and clear the stash too early (the exact reset-before-read hazard
            // this design avoids). Do not add a local above this line.
            struct EngineClassStashClear {
                ~EngineClassStashClear() { detail::tls_engine_principal() = false; }
            } engine_class_stash_clear;

            // Per-principal quota (PR 4.4) — release the concurrency slot
            // (if any) admitted for this request at pre-routing. A no-op for
            // denied/streaming/non-engine requests, which never stash one.
            detail::tls_quota_slot().reset();

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

            // principal_class: bounded actor class (ADR-1005, execution-plan
            // PR 1.2) — human / agent / none / engine. "engine" is live as of
            // PR 4.5: principal_class_resolved reads the stash set by the
            // pre-routing chokepoint from the RESOLVED session, falling back
            // to presentation-based principal_class_of otherwise. See
            // principal_class.hpp for the full hybrid-basis contract.
            metrics_
                .counter("yuzu_http_requests_total",
                         {{"method", req.method},
                          {"status", std::to_string(res.status)},
                          {"principal_class", std::string(principal_class_resolved(req))}})
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
            // Refresh NVD backfill gauges (multi-hour background job — needs to be
            // observable; governance sre BLOCKING).
            if (nvd_db_ && nvd_db_->is_open()) {
                metrics_.gauge("yuzu_nvd_total_cves")
                    .set(static_cast<double>(nvd_db_->total_cve_count()));
                if (nvd_sync_) {
                    auto st = nvd_sync_->status();
                    metrics_.gauge("yuzu_nvd_backfill_complete").set(st.backfill_complete ? 1 : 0);
                    // Pull model (#1909): the manager holds the authoritative monotonic
                    // per-reason failure counts; emit them as yuzu_nvd_sync_failures_total by
                    // incrementing the exported series by the delta since the last scrape
                    // (Counter has no set()). No sync-thread→metrics_ callback → no teardown race.
                    // The whole loop is serialized so two CONCURRENT /metrics scrapes (an HA
                    // Prometheus pair) can't both read the same value(), compute the same delta,
                    // and double-increment the counter (which would then stall until the real
                    // tally re-exceeds it).
                    std::lock_guard<std::mutex> emit_lock{nvd_metrics_scrape_mu_};
                    for (auto r : kNvdCountedReasons) {
                        const int i = nvd_reason_index(r);
                        auto& c = metrics_.counter("yuzu_nvd_sync_failures_total",
                                                   {{"reason", nvd_reason_label(r)}});
                        const double delta = static_cast<double>(st.failure_counts[i]) - c.value();
                        if (delta > 0)
                            c.increment(delta);
                    }
                }
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

            // Store health — all checks are constant-time and perform no DB I/O.
            // Match /readyz's non-lease-consuming Postgres reachability signal:
            // valid() checks configuration and the breaker records real connect
            // failures without treating a saturated-but-healthy pool as down.
            bool pg_pool_ok = pg_pool_ && pg_pool_->valid() && !pg_pool_->connect_breaker_open();
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
            // Born-on-Postgres stores (ADR-0012). They were wired into /readyz but
            // not here, so /healthz could report "healthy" with a degraded store —
            // the same gap the Guardian/CA rows above closed. The server fails
            // closed at boot if PG is unreachable, so on a running server these are
            // normally open; the row catches a post-boot store-level failure.
            bool offline_endpoint_ok =
                offline_endpoint_store_ && offline_endpoint_store_->is_open();
            bool software_inventory_ok =
                software_inventory_store_ && software_inventory_store_->is_open();
            bool vuln_finding_ok = vuln_finding_store_ && vuln_finding_store_->is_open();
            bool app_perf_daily_ok = app_perf_daily_store_ && app_perf_daily_store_->is_open();
            bool app_perf_fleet_ok = app_perf_fleet_store_ && app_perf_fleet_store_->is_open();
            bool device_inventory_ok =
                device_inventory_store_ && device_inventory_store_->is_open();
            // Generic InventoryStore (ADR-0037) — was wired into /readyz but missing
            // here (governance IS2: the file's own comments document this exact
            // readyz-vs-healthz drift as a previously-shipped bug for other stores).
            bool inventory_ok = inventory_store_ && inventory_store_->is_open();
            // Load-bearing for the MCP write surface + REST approvals (sre-BLOCKING-1).
            bool approval_ok = approval_manager_ && approval_manager_->is_open();
            // Management-group CONFINEMENT substrate (ADR-0042) — was wired into
            // /readyz but missing here, the same readyz-vs-healthz drift the
            // rows above document. A degraded confinement store fails RbacStore's
            // list gate closed, so surface it.
            bool mgmt_group_ok = mgmt_group_store_ && mgmt_group_store_->is_open();

            // Determine overall status
            bool all_stores_ok =
                pg_pool_ok && response_ok && audit_ok && instruction_ok && policy_ok &&
                guaranteed_state_ok && baseline_ok && offload_target_ok && ca_ok &&
                offline_endpoint_ok && software_inventory_ok && vuln_finding_ok &&
                app_perf_daily_ok && app_perf_fleet_ok && device_inventory_ok && inventory_ok &&
                approval_ok && mgmt_group_ok;
            std::string status = all_stores_ok ? "healthy" : "degraded";

            nlohmann::json health = {
                {"status", status},
                {"uptime_seconds", uptime_sec},
                {"agents", {{"online", online}}}, // pending added below for authed callers
                {"stores",
                 {{"pg_pool", pg_pool_ok ? "ok" : "error"},
                  {"responses", response_ok ? "ok" : "error"},
                  {"audit", audit_ok ? "ok" : "error"},
                  {"instructions", instruction_ok ? "ok" : "error"},
                  {"policies", policy_ok ? "ok" : "error"},
                  {"guaranteed_state", guaranteed_state_ok ? "ok" : "error"},
                  {"baselines", baseline_ok ? "ok" : "error"},
                  {"offload_target", offload_target_ok ? "ok" : "error"},
                  {"ca", ca_ok ? "ok" : "error"},
                  {"offline_endpoint_store", offline_endpoint_ok ? "ok" : "error"},
                  {"software_inventory_store", software_inventory_ok ? "ok" : "error"},
                  {"vuln_finding_store", vuln_finding_ok ? "ok" : "error"},
                  {"app_perf_daily_store", app_perf_daily_ok ? "ok" : "error"},
                  {"app_perf_fleet_store", app_perf_fleet_ok ? "ok" : "error"},
                  {"device_inventory_store", device_inventory_ok ? "ok" : "error"},
                  {"inventory_store", inventory_ok ? "ok" : "error"},
                  {"management_group_store", mgmt_group_ok ? "ok" : "error"}}},
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
                {"engine_principal_store",
                 engine_principal_store_ && engine_principal_store_->is_open()},
                // Load-bearing for the MCP write surface + REST /api/approvals/*
                // (governance sre-BLOCKING-1). is_open() is false after a failed
                // consumed_at migration, so a broken approval schema fails readyz.
                {"approval_manager", approval_manager_ && approval_manager_->is_open()},
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
                // ADR-0016 born-on-Pg store. Fail-closed at boot, but a not-open
                // state post-boot makes ReportInventory silently ack with no
                // ingest and no readiness signal — surface it (gov Pattern E).
                {"software_inventory_store",
                 software_inventory_store_ && software_inventory_store_->is_open()},
                // CAVM born-on-PG store (ADR-0012). Fail-closed at boot; a
                // not-open post-boot state means the PR-4 matching engine would
                // silently no-op findings persistence — surface it (Pattern E).
                {"vuln_finding_store",
                 vuln_finding_store_ && vuln_finding_store_->is_open()},
                // Periodic Access Reviews (SOC 2 CC6.2) born-on-PG store. AUTHORITATIVE
                // per ADR-0012 §1 — the /api/v1/access-reviews campaign lifecycle
                // (open/attest/close) is dead without it. The read-only export route
                // does not depend on this store, but the campaign-based evidence surface
                // is the feature's core deliverable, so a not-open state must be visible
                // at /readyz, not just returning 503 per-request unnoticed.
                {"access_review_store",
                 access_review_store_ && access_review_store_->is_open()},
                {"app_perf_daily_store",
                 app_perf_daily_store_ && app_perf_daily_store_->is_open()},
                {"app_perf_fleet_store",
                 app_perf_fleet_store_ && app_perf_fleet_store_->is_open()},
                // ADR-0016 device-CI born-on-Pg store — same rationale as the
                // software_inventory_store row above (silent no-ingest ack if dead).
                {"device_inventory_store",
                 device_inventory_store_ && device_inventory_store_->is_open()},
                // ADR-0024 SLE born-on-Pg stores (roadmap G-10, HC-1 Pattern E). Same
                // rationale as the inventory stores: fail-closed at boot, but a not-open
                // state post-boot makes ReportInventory silently ack the licensing blob
                // with no ingest (software_licensing_store) and the /api/v1/sle/* reads
                // degrade to 503 (both) — surface it so an LB/operator sees the half-state.
                {"software_licensing_store",
                 software_licensing_store_ && software_licensing_store_->is_open()},
                {"product_registry_store",
                 product_registry_store_ && product_registry_store_->is_open()},
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
                // against it. A failed migration/backfill (migrated to Postgres,
                // schema `result_set_store`, ADR-0036) would silently degrade
                // every scoped dispatch to zero targets while /readyz reported
                // "ready" — this construction is already fail-closed
                // (startup_failed_) per ADR-0012 §1, but the readyz entry stays
                // as belt-and-braces against a runtime is_open() flip.
                {"result_set_store", result_set_store_ && result_set_store_->is_open()},
                // PKI PR2: ca.db is load-bearing only when the install is on
                // built-in default certs (PR3+ make it load-bearing for mTLS
                // issuance/revocation). When the operator brought their own certs
                // it is not on the request path, so report ok.
                {"ca_store", !cfg_.using_default_certs || (ca_store_ && ca_store_->is_open())},
                {"ca_root", !cfg_.using_default_certs || (ca_store_ && ca_store_->has_root())},
                // SRE Gate 6 HC-1: ScimStore is only constructed when
                // --scim-enable is set (opt-in, mirrors the ca_store pattern
                // above); a failed open/migration would otherwise silently
                // reject every /scim/v2/* request while /readyz reported
                // "ready". H3 (2026-07-08 review, defense-in-depth): also
                // requires has_token() — the primary fix is that a failed
                // set_token() at boot now sets startup_failed_ (server never
                // reaches run()'s serve loop at all), but this term keeps
                // /readyz honest on its own terms too, independent of that
                // guard.
                {"scim_store", !cfg_.scim_enable ||
                                   (scim_store_ && scim_store_->is_open() &&
                                    scim_store_->has_token())},
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
            // #1837: `username` is the STABLE authorization principal (an
            // opaque `oidc:<iss>#<sub>` id for SSO sessions) — never render
            // it alone as the nav-bar identity. `display_name` is the
            // human-readable label consumed by every page's nav/context
            // bar JS below; falls back to `username` for a legacy session
            // created before this field existed.
            auto j = nlohmann::json(
                {{"username", session->username},
                {"display_name",
                 session->display_name.empty() ? session->username : session->display_name},
                {"role", auth::role_to_string(session->role)}});
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
                action_label, cfg_.mfa_enforcement, &metrics_);
        };

        // -- Settings routes (extracted to settings_routes.cpp) ---------------
        settings_routes_ = std::make_unique<SettingsRoutes>();
        // PR 4.3 (T13): wire the LIVE owner-delete guard + admin console
        // fragment. Nullable — a null/unwired engine_principal_store_ leaves
        // the guard permissive (documented on set_engine_principal_store) and
        // the console fragment renders "not configured", same posture as
        // every other optional-store wiring in this file.
        if (engine_principal_store_) {
            settings_routes_->set_engine_principal_store(engine_principal_store_.get());
        }
        // Access-review (CC6.2) Settings fragment deps — nullable, same
        // deferred-wiring posture as set_engine_principal_store above: an
        // unwired store leaves the fragment rendering an "unavailable" notice
        // rather than crashing. auth_db comes from auth_mgr_; api_token_store_
        // + engine_principal_store_ are already wired above/via register_routes.
        if (rbac_store_) {
            settings_routes_->set_rbac_store(rbac_store_.get());
        }
        if (access_review_store_) {
            settings_routes_->set_access_review_store(access_review_store_.get());
        }
        if (directory_sync_) {
            settings_routes_->set_access_review_directory_sync(directory_sync_.get());
        }
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
        web_server_->Get("/events", [this](const httplib::Request& req, httplib::Response& res) {
            // ADMISSION CONTROL (ADR-0034). Every connection holds an httplib worker for
            // its whole life, so it takes a lease like every other streaming surface.
            // This route IS session-gated: `/events` is not in `is_login_exempt_path`,
            // and the pre-routing chokepoint 401s a caller with no session by name
            // (alongside `/api/` and `/mcp/`), so the handler only ever runs for an
            // authenticated operator. What the lease bounds here is therefore an
            // AUTHENTICATED thread-pinning path, not a pre-auth one.
            // The anonymous branch below is unreachable today and kept only as
            // defence-in-depth against a future change to the exempt list — it must not
            // be read as evidence that this surface is open. The residual defect on this
            // route is the missing per-connection queue cap (`/api/v1/events` opts into
            // `kPerConnectionQueueCapDefault`; this one does not), which the lease does
            // NOT address — see ADR-0034 Decision 1.
            std::string principal = "anonymous";
            std::size_t per_principal = detail::kPerPrincipalAnonymous;
            if (auth_routes_) {
                if (auto sess = auth_routes_->resolve_session(req)) {
                    principal = sess->username;
                    per_principal = detail::kPerPrincipalDashboard;
                }
            }
            auto lease = std::make_shared<detail::StreamBudget::Lease>();
            if (stream_budget_) {
                auto admitted = stream_budget_->try_acquire(detail::SseSurface::kLegacyEvents,
                                                            principal, per_principal);
                if (!admitted.lease) {
                    res.status = 429;
                    res.set_header("Retry-After", "5");
                    res.set_content("too many live streams open", "text/plain; charset=utf-8");
                    return;
                }
                *lease = std::move(admitted.lease);
            }

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
            // UP-1: adopt any pending engine QuotaSlot into this stream's
            // resource-releaser (see is_streaming_path/adopt_quota_slot_
            // into_stream in principal_quota_gate.hpp) so the concurrency
            // reservation survives for the stream's actual lifetime instead
            // of releasing early at post-routing.
            res.set_chunked_content_provider(
                "text/event-stream",
                [sink_state](size_t offset, httplib::DataSink& sink) -> bool {
                    return detail::sse_content_provider(sink_state, offset, sink);
                },
                detail::adopt_quota_slot_into_stream(
                    [sink_state, bus, lease](bool success) noexcept {
                        // noexcept for parity with the three sibling releasers: this runs
                        // from ~Response, and sse_resource_release is now noexcept at source
                        // (event_bus.hpp), so the whole chain is terminate-safe.
                        detail::sse_resource_release(sink_state, *bus, success);
                        // `lease` dies here — the worker returns to the one shared budget.
                    }));
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
                             // "enabled" reflects whether the sync manager exists, not
                             // merely whether the DB file is open: under --no-nvd-sync the
                             // catalog DB is still open (for matching) but sync is off, so
                             // reporting enabled=true then 503-ing POST /api/nvd/sync was
                             // contradictory (#1889 review r2).
                             j["enabled"] = (nvd_sync_ != nullptr);
                             j["total_cves"] = nvd_db_->total_cve_count();
                             if (nvd_sync_) {
                                 auto st = nvd_sync_->status();
                                 j["syncing"] = st.syncing;
                                 j["last_sync_time"] = st.last_sync_time;
                                 j["last_error"] = st.last_error;
                                 j["backfill_complete"] = st.backfill_complete;
                                 j["backfill_oldest_published"] = st.backfill_oldest_published;
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
            // Ask the background loop to sync at its next wake and return at once.
            // (A detached thread here could outlive the manager and use-after-free
            // db_/fetcher_ during the hours-long backfill — governance BLOCKING.)
            nvd_sync_->request_sync();
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
            // Parse inventory: JSON body with an "inventory" array of {name, version}.
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
            // SILENT-DROP helper, kept deliberately: it returns {} for omitted,
            // empty, non-array and parse-failure alike. That erasure is #2500's
            // defect, and this call is safe ONLY because `check_targeting_shape`
            // runs below on the separately-parsed `body` and refuses every shape
            // whose erasure would matter. Moving this below that check, or
            // removing it, requires re-reading that ordering first.
            auto agent_ids = extract_json_string_array(req.body, "agent_ids");

            if (plugin.empty() || action.empty()) {
                res.status = 400;
                res.set_content(
                    R"({"error":{"code":400,"message":"plugin and action are required"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            // plugin/action are IDENTIFIERS. Bounding them here is what actually
            // closes the audit-detail forgery that a previous round only half
            // fixed: `sanitize_for_log` normalises control bytes, but leaves
            // space, `=`, `:` and `-` alone, so a caller could still plant
            //     plugin = "noop reason=agent_ids_empty"
            //     action = "noop \u2192 4000 agent(s)"
            // and produce a durable denial row that mimics the SUCCESS format
            // (`reason=<r> <plugin>:<action>` vs `plugin:action \u2192 N agent(s)`).
            // Byte-shape safety is not field-structure safety. Validating the
            // input is also what bounds the row size and keeps the column
            // well-formed, which is three problems closed at one gate instead of
            // three sanitisers at three sinks.
            //
            // Charset matches what shipped content actually uses - every
            // `plugin`/`action` in content/definitions/*.yaml fits this, and
            // dotted server actions (`workflow.list`) are live content, so `.`
            // must stay legal. Length matches MCP's kExecInstrIdentMaxLen so the
            // two execute surfaces agree on what an identifier is.
            {
                constexpr size_t kIdentMax = 128;
                const auto bad_ident = [](const std::string& v) {
                    if (v.size() > kIdentMax)
                        return true;
                    return std::any_of(v.begin(), v.end(), [](unsigned char c) {
                        return !(std::isalnum(c) || c == '_' || c == '.' || c == '-');
                    });
                };
                if (bad_ident(plugin) || bad_ident(action)) {
                    res.status = 400;
                    res.set_content(
                        R"j({"error":{"code":400,"message":"plugin and action must be identifiers ([A-Za-z0-9_.-], max 128 bytes)"},"meta":{"api_version":"v1"}})j",
                        "application/json");
                    return;
                }
            }

            // All commands require Execution:Execute permission
            if (!require_permission(req, res, "Execution", "Execute"))
                return;

            // ── Targeting shape: supplied-but-names-nothing is an ERROR (#2500) ──
            // Run on the PARSED BODY, never on `agent_ids` above.
            // `extract_json_string_array` returns {} for omitted, empty, not-an-array
            // AND parse-failure alike, and that erasure IS this defect: a check
            // written against its output cannot see `{"agent_ids":"dev-01"}` or
            // `{"scope":5}` at all, and would ship half the bug with green tests.
            //
            // Placed AFTER require_permission so a refusal is attributable to a
            // principal and can carry an audit row; before any dispatch-shaped work.
            // The `plugin`/`action` emptiness check above deliberately stays where it
            // is rather than being subsumed the way `ident_empty` subsumed MCP's: it
            // currently runs BEFORE require_permission, and moving an auth-adjacent
            // check is not something to do silently inside a targeting fix.
            // Parsed with allow_exceptions=false rather than a try/catch that falls
            // through. The earlier form set "named no target" in its catch and
            // CONTINUED, arguing the catch was unreachable because a body that does
            // not parse yields an empty `plugin`. That holds for parse errors — but
            // not for std::bad_alloc: under memory pressure a body of
            // {"agent_ids":[]} would have landed in the catch and proceeded to
            // broadcast. A fail-OPEN catch inside the fix for a widening defect
            // (governance, cpp-safety). A discarded value yields contains()==false
            // on every query below, so an unparseable body is refused here rather
            // than continuing with unknown targeting.
            const auto body = nlohmann::json::parse(req.body, nullptr, /*allow_exceptions=*/false);
            // `check_targeting_shape` requires an OBJECT: contains() is false for an
            // array or scalar, so `["dev-1"]` would read as "named no target" and
            // broadcast — the very shape this route is being fixed for. Three Gate-3
            // reviewers found this independently; the precondition is enforced here
            // and pinned by a route test, not left as a comment on the header.
            if (!body.is_object()) {
                // Counted and audited like every other refusal in this family.
                // The fold's own argument against an uncounted refusal applies
                // here: an invisible one cannot reach the alert this change
                // ships, and this is the shape three reviewers had to find by
                // reading rather than by watching a dashboard.
                metrics_
                    .counter("yuzu_server_dispatch_target_rejected_total",
                             {{"route", "command"}, {"reason", std::string(kReasonBodyType)}})
                    .increment();
                // Capture the audit return and surface partial-success, per the
                // AuditFn contract (SOC 2 CC6.6, PR #883) and the
                // instruction.import precedent. The status stays 400 — the
                // request WAS invalid, and answering 503 because we could not
                // record that would trade a correct refusal for an outage.
                const bool audit_ok = audit_log(req, "command.dispatch", "denied", "command", "",
                                                std::string("reason=") + std::string(kReasonBodyType));
                if (!audit_ok)
                    res.set_header("Sec-Audit-Failed", "true");
                res.status = 400;
                // `audit_emitted` is omitted entirely when no audit store is
                // configured: audit_log() returns true in that case, so
                // reporting `true` would assert a row landed on a deployment
                // that keeps none. Absent means "no claim", not "false".
                nlohmann::json err{{"error",
                                    {{"code", 400},
                                     {"message", "request body must be a JSON object"}}},
                                   {"meta", {{"api_version", "v1"}}}};
                if (audit_store_)
                    err["audit_emitted"] = audit_ok;
                res.set_content(err.dump(), "application/json");
                return;
            }
            if (auto bv = yuzu::server::check_targeting_shape(body)) {
                metrics_
                    .counter("yuzu_server_dispatch_target_rejected_total",
                             {{"route", "command"}, {"reason", bv->reason}})
                    .increment();
                // The detail carries WHAT was being attempted, not just why it
                // was refused. The success row records `plugin:action -> N
                // agent(s)`; a denial that records only `reason=` lets an
                // auditor show that an operator was blocked but not what they
                // were trying to run — on a control whose whole purpose is
                // reconstructing near-miss blast radius (governance, compliance).
                // `plugin`/`action` are CALLER-SUPPLIED and this route bounds
                // neither length nor charset (unlike MCP's kExecInstrIdentMaxLen).
                // Concatenating them raw into an evidence field let a caller
                // forge a row that mimics the success format
                // (`plugin:action -> N agent(s)`) and write an arbitrarily large
                // durable row before any dispatch — turning the field this fold
                // added FOR blast-radius reconstruction into the thing an
                // attacker writes. Sanitised through the same helper the
                // on-behalf-of guard uses for untrusted log text: control chars
                // and CR/LF become '?', length capped (governance, security).
                const bool audit_ok =
                    audit_log(req, "command.dispatch", "denied", "command", "",
                              std::string("reason=") + bv->reason + " " +
                                  onbehalf::sanitize_for_log(plugin, 128) + ":" +
                                  onbehalf::sanitize_for_log(action, 128));
                if (!audit_ok)
                    res.set_header("Sec-Audit-Failed", "true");
                res.status = 400;
                // Same gate as the body_type denial above: with no audit store
                // configured, audit_log() returns true without writing, so an
                // unconditional `true` here would assert a row landed on a
                // deployment that keeps none. Absent = no claim.
                nlohmann::json err{{"error", {{"code", 400}, {"message", bv->message}}},
                                   {"meta", {{"api_version", "v1"}}}};
                if (audit_store_)
                    err["audit_emitted"] = audit_ok;
                res.set_content(err.dump(), "application/json");
                return;
            }
            const bool named_target = yuzu::server::targeting_supplied(body);

            // Per-action securable elevation + scope confinement for DESTRUCTIVE
            // generic-dispatch actions (governance HIGH #2). /api/command otherwise
            // base-gates only Execution:Execute and applies NO per-device visibility to
            // explicit agent_ids — a systemic property of this escape hatch tracked
            // separately (Tr3kkR/Yuzu#1788). An irreversible action (e.g.
            // tar.purge_source) must NOT inherit that: require its real securable AND
            // confine the targets to the operator's visible agents, refusing untargeted
            // broadcast/scope fan-out. The dedicated POST /api/v1/tar/retention-paused/
            // purge is the first-class structured surface; this keeps the generic path
            // from being a weaker one on AUTHZ. (Observability is still weaker here: a
            // purge via /api/command audits under the generic `command.dispatch` verb +
            // yuzu_commands_dispatched_total, not tar.source.purge / the domain metric —
            // domain-verb emission on this path is tracked in Tr3kkR/Yuzu#1787.)
            {
                static const std::unordered_map<std::string,
                                                std::pair<std::string, std::string>>
                    kDestructiveActionSecurable = {
                        {"tar.purge_source", {"Infrastructure", "Delete"}},
                    };
                std::string dkey = plugin + "." + action;
                std::transform(dkey.begin(), dkey.end(), dkey.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (auto it = kDestructiveActionSecurable.find(dkey);
                    it != kDestructiveActionSecurable.end()) {
                    if (!require_permission(req, res, it->second.first, it->second.second))
                        return;
                    // Destructive dispatch must be explicitly targeted + in scope.
                    if (agent_ids.empty() || !extract_json_string(body, "scope").empty()) {
                        res.status = 400;
                        res.set_content(
                            R"({"error":{"code":400,"message":"destructive action requires explicit in-scope agent_ids; broadcast and scope fan-out are refused"},"meta":{"api_version":"v1"}})",
                            "application/json");
                        return;
                    }
                    // Confine to the operator's visible agents (fail-closed: an absent
                    // mgmt-group store filters to empty → 404, same posture as the
                    // dashboard fragment). Out-of-scope ids are silently dropped.
                    std::vector<std::string> filtered;
                    if (mgmt_group_store_) {
                        auto s = require_auth(req, res);
                        if (!s) return;
                        // ADR-0042: nullopt (store degraded) → empty visible set → 404.
                        auto vis = mgmt_group_store_->get_visible_agents(s->username);
                        std::unordered_set<std::string> visible;
                        if (vis)
                            visible.insert(vis->begin(), vis->end());
                        for (const auto& aid : agent_ids)
                            if (visible.count(aid))
                                filtered.push_back(aid);
                    }
                    agent_ids = std::move(filtered);
                    if (agent_ids.empty()) {
                        res.status = 404;
                        res.set_content(
                            R"({"error":{"code":404,"message":"no reachable in-scope agent"},"meta":{"api_version":"v1"}})",
                            "application/json");
                        return;
                    }
                }
            }

            // ── #1788: per-device visibility on EVERY dispatch arm ──────────────
            // Everything above gates a possibly-GLOBAL Execution:Execute (or the
            // destructive-action securable) and, for the destructive list only,
            // narrows `agent_ids` to a coarser ManagementGroupStore visibility.
            // Nothing narrowed the actual send set on ANY of the four dispatch
            // arms below (explicit agent_ids, broadcast, Group, Scope) to the
            // operator's own Execution:Execute visibility — a management-group-
            // confined operator could reach a device outside their confinement
            // through any of them. Derive ONE permission-specific visible set
            // here and intersect every arm against it before send_to
            // (`yuzu::server::authz::in_scope`/`filter_to_scope`).
            //
            // Composition mirrors `RbacStore::check_scoped_permission`'s OWN
            // internal order (global first, else the ADR-0017 scoped set) —
            // #1715(b): a global ALLOW overrides any group deny, so it is read
            // via the SAME public `check_permission` call, never re-derived.
            // JIT admin elevation and a service-scoped token's ITServiceOwner
            // grant are the two OTHER ways `require_permission` above already
            // admits a caller with no matching `principal_roles` row (neither
            // is stored as a group-scoped grant `visible_agents_for_permission`
            // could see) — both are treated as unfiltered here too, or a caller
            // `require_permission` deliberately admitted would be silently
            // emptied out below. Fail-closed: any store error narrows to
            // "nothing visible", never "everything" — never re-decides the
            // frozen #1715/INV-7 precedence those RbacStore calls already
            // resolve, only composes on top of it.
            auto sess = require_auth(req, res);
            if (!sess)
                return; // require_auth already wrote the response

            // D3: the no-agent 503 short-circuit sits BEFORE deriving
            // exec_visible — that derivation runs an RBAC/tag-store lookup
            // that is wasted work on the (common, cheap-to-detect) no-agent
            // path, which never reaches a dispatch decision anyway.
            if (!registry_.has_any()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"no agent connected"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }

            yuzu::server::authz::VisibleSet exec_visible = derive_exec_visible(*sess);

            auto command_id =
                plugin + "-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));

            detail::pb::CommandRequest cmd;
            cmd.set_command_id(command_id);
            cmd.set_plugin(plugin);
            cmd.set_action(action);

            // Parameters: pass-through key-value pairs to the agent plugin
            {
                auto params_map = extract_json_string_map(body, "params");
                for (const auto& [k, v] : params_map) {
                    (*cmd.mutable_parameters())[k] = v;
                }
            }

            // Stagger/delay: prevent thundering herd on large-fleet dispatch
            auto stagger = extract_json_int(body, "stagger", 0);
            auto delay = extract_json_int(body, "delay", 0);
            if (stagger > 0)
                cmd.set_stagger_seconds(stagger);
            if (delay > 0)
                cmd.set_delay_seconds(delay);

            agent_service_.record_send_time(command_id);

            // Check for scope-based targeting. Reuses the parsed body like the
            // other post-auth reads; this site was missed when the rest were
            // converted and re-parsed the whole body to read a key the handler
            // already had (governance).
            auto scope_expr = extract_json_string(body, "scope");

            int sent = 0;
            // `__all__` is the PUBLISHED ground scope kind (/discover/scope-kinds,
            // the MCP execute_instruction schema, docs/scope-walking-design.md), and
            // it is handled here as "no scope expression" so the ordering matches the
            // shared closure and the MCP one exactly: an explicit agent_ids list
            // still wins. Before #2500 this route fed `__all__` to scope::parse,
            // which fails, so the caller got a 503 having reached nobody — while the
            // sibling instruction-execute route broadcast on the same string. One
            // advertised scope kind must not mean two things across sibling REST
            // routes (governance, security MEDIUM).
            // #1788: the injected sink shared with `ServerImpl::dispatch_confined`
            // (dispatch_confined_arms.hpp / A-3's make_confined_dispatch_sink).
            // This route keeps its own target resolution, audit rows and HTTP
            // shaping — which is why it is not simply absorbed by that seam —
            // but the DECISION OF WHO IS REACHED is the shared one, so the two
            // can no longer drift.
            const auto confined_sink = make_confined_dispatch_sink(cmd);
            const auto dispatch_broadcast = [&]() -> int {
                return yuzu::server::dispatch_confined_arms(
                    yuzu::server::DispatchArm::Broadcast, {}, exec_visible,
                    /*broadcast_on_none=*/true, confined_sink);
            };

            const auto arm = yuzu::server::classify_dispatch_arm(!agent_ids.empty(), scope_expr);
            if (arm == yuzu::server::DispatchArm::Group) {
                // Group-based dispatch — resolve group members here, then let the
                // shared seam intersect (#1788): a management group is a targeting
                // mechanism, not an authz exemption from it.
                auto group_id = scope_expr.substr(6);
                std::vector<std::string> members;
                if (mgmt_group_store_)
                    for (const auto& m : mgmt_group_store_->get_members(group_id))
                        members.push_back(m.agent_id);
                yuzu::server::ConfinedDispatchTargets t;
                t.group_members = &members;
                sent = yuzu::server::dispatch_confined_arms(arm, t, exec_visible,
                                                            /*broadcast_on_none=*/true,
                                                            confined_sink);
            } else if (arm == yuzu::server::DispatchArm::Scope) {
                // Scope expression dispatch.
                // Owner principal for from_result_set: resolution (review B1).
                // This raw path is untracked (no execution row), so read the
                // session directly; auth already passed require_permission above.
                std::string principal, principal_role;
                if (auto s = require_auth(req, res)) {
                    principal = s->username;
                    principal_role = auth::role_to_string(s->role);
                }
                // A-3: the ladder itself (alias resolution -> owner-check gate
                // -> parse -> registry evaluation, each step fail-closed per
                // ADR-0036) is the ~55 lines that were byte-identical with
                // `ServerImpl::dispatch_confined`'s Scope arm — shared now via
                // `resolve_scope_targets` (dispatch_scope_ladder.hpp). A DB
                // error or failed owner check at any step ABORTS (nullopt),
                // `sent` stays 0, and the shared "sent == 0 -> 503" fallback
                // below fires. This route ALONE reacts to a parse failure with
                // its own 400 (no `res` to write to on the dispatch_confined
                // side), which is why it is not simply absorbed by that seam.
                yuzu::server::ScopeLadderAudit audit;
                audit.resolution_failed = [this, &principal, &principal_role,
                                           &command_id](const std::string& ref) {
                    audit_scope_resolution_failed(principal, principal_role, command_id, ref);
                };
                audit.evaluation_aborted = [this, &principal, &principal_role,
                                            &command_id](const std::string& reason) {
                    audit_scope_evaluation_aborted(principal, principal_role, command_id, reason);
                };
                auto ladder = yuzu::server::resolve_scope_targets(
                    scope_expr, principal, result_set_store_.get(),
                    [this, &principal](const yuzu::scope::Expression& parsed) {
                        return registry_.evaluate_scope(parsed, tag_store_.get(),
                                                        custom_properties_store_.get(),
                                                        result_set_store_.get(), principal);
                    },
                    audit);
                if (ladder.parse_error) {
                    res.status = 400;
                    res.set_content(
                        nlohmann::json({{"error", "invalid scope: " + *ladder.parse_error}})
                            .dump(),
                        "application/json");
                    return;
                }
                if (ladder.matched) {
                    // #1788: a scope match is a targeting mechanism, not an
                    // authz exemption — the shared seam intersects it against
                    // the operator's Execution:Execute visible set before
                    // dispatch.
                    yuzu::server::ConfinedDispatchTargets t;
                    t.scope_matched = &*ladder.matched;
                    sent = yuzu::server::dispatch_confined_arms(
                        arm, t, exec_visible, /*broadcast_on_none=*/true, confined_sink);
                }
                // else: the ladder already audited the abort (db_degraded /
                // owner_check_failed / principal_unresolved) — sent stays 0.
            } else if (arm == yuzu::server::DispatchArm::Ids) {
                // #1788: an explicit id list is the arm #1788 named directly —
                // the shared seam intersects it against the operator's
                // Execution:Execute visible set before dispatch; a hidden id is
                // silently dropped, not an error (matching how a scope/group
                // match that resolves to nothing behaves here — the shape check
                // above already refused an EMPTY supplied list, this is a
                // non-empty list narrowed by visibility, a different thing).
                yuzu::server::ConfinedDispatchTargets t;
                t.agent_ids = &agent_ids;
                sent = yuzu::server::dispatch_confined_arms(arm, t, exec_visible,
                                                            /*broadcast_on_none=*/true,
                                                            confined_sink);
            } else if (arm == yuzu::server::DispatchArm::Broadcast) {
                // Explicitly asked for the fleet by its published name — #1788
                // still narrows delivery to the operator's visible set; the
                // NAME `__all__` is preserved (never rejected, never reread as
                // "no target"), only the SEND SET composes with visibility.
                sent = dispatch_broadcast();
            } else {
                // Broadcast ONLY when the caller named no target at all (#2500).
                // A target that was SUPPLIED but resolved to nothing must never
                // widen to the whole fleet — `{"agent_ids": []}` from a device
                // filter that matched nothing is the likelier shape than the
                // type-confused one, and it read as "no devices" to whoever sent it.
                //
                // The shape check ~150 lines above already refuses those bodies, so
                // this branch is UNREACHABLE today. It is second line of defence,
                // not the fix: the silent-drop `extract_json_string_array` call and
                // this sink sit far apart with the permission gate, the destructive
                // block and the params extraction between them, and this is the one
                // place where a reorder turns a specific-looking target list into
                // the entire fleet. Falsifiable on its own terms — neuter the shape
                // check and `{"agent_ids": []}` is still refused here.
                //
                // (An earlier version of this comment said the pre-#2500 caller
                // "got a 503"; the base code answered 400 "invalid scope". The
                // docs and tests were corrected in an earlier fold and this
                // comment was missed.)
                if (named_target) {
                    // Derive the label from which field was actually supplied,
                    // as the MCP sink does. Hardcoding `agent_ids_empty` would
                    // mislabel a `scope`-only violation if this arm ever became
                    // reachable, and a wrong reason on a fleet-safety refusal is
                    // worse than no reason.
                    const auto sink_reason = body.contains("agent_ids")
                                                 ? kTargetingShapeReasons[1]  // agent_ids_empty
                                                 : kTargetingShapeReasons[4]; // scope_empty
                    metrics_
                        .counter("yuzu_server_dispatch_target_rejected_total",
                                 {{"route", "command"}, {"reason", std::string(sink_reason)}})
                        .increment();
                    // Empty target_id, matching the source-side denial above: the
                    // same verb must not carry two different target shapes, and a
                    // command_id for a command that was never dispatched reads in
                    // the audit trail as though one was.
                    const bool audit_ok =
                        audit_log(req, "command.dispatch", "denied", "command", "",
                                  "reason=" + std::string(sink_reason) + " " +
                                      onbehalf::sanitize_for_log(plugin, 128) + ":" +
                                      onbehalf::sanitize_for_log(action, 128));
                    if (!audit_ok)
                        res.set_header("Sec-Audit-Failed", "true");
                    res.status = 400;
                    nlohmann::json err{
                        {"error",
                         {{"code", 400},
                          {"message", "a targeting argument was supplied but resolved to no "
                                      "target; omit it entirely to target all agents"}}},
                        {"meta", {{"api_version", "v1"}}}};
                    if (audit_store_)
                        err["audit_emitted"] = audit_ok;
                    res.set_content(err.dump(), "application/json");
                    return;
                }
                // #1788: an omitted target means "the whole fleet" (#2500) —
                // still narrowed to the operator's visible set, same as the
                // named Broadcast arm above.
                sent = dispatch_broadcast();
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
                              forward_legacy_command(req, "chargen", "chargen_start", res);
                          });

        web_server_->Post("/api/chargen/stop",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_permission(req, res, "Execution", "Execute"))
                                  return;
                              forward_legacy_command(req, "chargen", "chargen_stop", res);
                          });

        web_server_->Post("/api/procfetch/fetch",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_permission(req, res, "Execution", "Execute"))
                                  return;
                              forward_legacy_command(req, "procfetch", "procfetch_fetch", res);
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

            // #1634 management-group scope (filter-BEFORE-aggregate; same as MCP
            // aggregate_responses). The flat Response:Read gate is not a per-agent
            // ownership check, so resolve the in-scope agent set and push it into the
            // aggregate WHERE clause. Uses an EXPLICIT positive check, never the
            // "dropped==0 → unrestricted" inference (#1634 UP-1/2/3):
            //   * RBAC loaded & explicitly disabled → leave scope nullopt (open).
            //   * Global Response:Read holder → leave scope nullopt (correct totals at
            //     any scale; also the perf hoist — skips the distinct scan + per-agent
            //     loop). check_permission (not is_rbac_enabled) gates this, so a corrupt
            //     store can't take this branch.
            //   * Otherwise (group-scoped operator) → resolve and ALWAYS set scope,
            //     even to the empty set (`AND 1=0` → zero rows), never an unrestricted
            //     read. A distinct_agent_ids() read error returns 503 (store-availability
            //     failure is NOT "operator sees no agents" — it must not look like empty
            //     data; observability-conventions + agentic-first A4 + ADR-0016
            //     authoritative-reads, #1634 sre review).
            AggregateScope agg_scope; // nullopt = no restriction
            std::size_t agg_dropped = 0;
            if (auto session = require_auth(req, res)) {
                if (rbac_enforcement_in_effect(rbac_store_.get()) &&
                    !(rbac_store_ &&
                      rbac_store_->check_permission(session->username, "Response", "Read"))) {
                    auto distinct = response_store_->distinct_agent_ids(instruction_id);
                    if (!distinct) {
                        res.status = 503;
                        res.set_content(
                            R"({"error":{"code":503,"message":"response store unavailable"},"meta":{"api_version":"v1"}})",
                            "application/json");
                        return;
                    }
                    std::vector<std::string> in_scope;
                    in_scope.reserve(distinct->size());
                    for (auto& aid : *distinct)
                        if (response_agent_in_scope(session->username, aid))
                            in_scope.push_back(std::move(aid));
                    agg_dropped = distinct->size() - in_scope.size();
                    agg_scope = std::move(in_scope); // ALWAYS engaged in this branch
                }
            } else {
                return; // require_auth already wrote 401
            }
            // CC7.2 evidence: a scope-drop is a security-relevant filtering event — record
            // it so a cross-operator access attempt that was suppressed is auditable on this
            // surface too (#1634 compliance review; parity with the MCP denied row / the
            // visualization scope_dropped detail).
            if (agg_dropped > 0)
                (void)audit_log(req, "response.read", "denied", "Execution", instruction_id,
                                "scope_dropped=" + std::to_string(agg_dropped) + " surface=aggregate");

            auto results = response_store_->aggregate(instruction_id, aq, filter, agg_scope);

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

            // #1634 management-group scope: drop out-of-scope agents' rows before
            // export (mirrors MCP query_responses / the visualization reader). The
            // flat Response:Read gate is not a per-agent ownership check.
            std::size_t export_dropped = 0;
            if (auto session = require_auth(req, res)) {
                // #1634 UP-1: gate on rbac_enforcement_in_effect (NOT raw is_rbac_enabled)
                // so a corrupt/load-failed rbac.db enters the filter and fails closed via
                // response_agent_in_scope, rather than skipping it and serving the fleet.
                if (rbac_enforcement_in_effect(rbac_store_.get())) {
                    std::unordered_map<std::string, bool> memo;
                    std::vector<StoredResponse> visible;
                    visible.reserve(results.size());
                    for (auto& r : results) {
                        auto [m, ins] = memo.try_emplace(r.agent_id, false);
                        if (ins)
                            m->second = response_agent_in_scope(session->username, r.agent_id);
                        if (m->second)
                            visible.push_back(std::move(r));
                        else if (ins) // count each DISTINCT dropped agent once
                            ++export_dropped;
                    }
                    results.swap(visible);
                }
            } else {
                return; // require_auth already wrote 401
            }
            // CC7.2 evidence: record the scope-drop on this surface (#1634 compliance review).
            if (export_dropped > 0)
                (void)audit_log(req, "response.read", "denied", "Execution", instruction_id,
                                "scope_dropped=" + std::to_string(export_dropped) + " surface=export");

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

            // #1634 management-group scope: drop out-of-scope agents' rows before
            // serving (mirrors the export sibling above + MCP query_responses). The
            // flat Response:Read gate is not a per-agent ownership check.
            std::size_t get_dropped = 0;
            if (auto session = require_auth(req, res)) {
                // #1634 UP-1: gate on rbac_enforcement_in_effect (NOT raw is_rbac_enabled)
                // so a corrupt/load-failed rbac.db enters the filter and fails closed via
                // response_agent_in_scope, rather than skipping it and serving the fleet.
                if (rbac_enforcement_in_effect(rbac_store_.get())) {
                    std::unordered_map<std::string, bool> memo;
                    std::vector<StoredResponse> visible;
                    visible.reserve(results.size());
                    for (auto& r : results) {
                        auto [m, ins] = memo.try_emplace(r.agent_id, false);
                        if (ins)
                            m->second = response_agent_in_scope(session->username, r.agent_id);
                        if (m->second)
                            visible.push_back(std::move(r));
                        else if (ins) // count each DISTINCT dropped agent once
                            ++get_dropped;
                    }
                    results.swap(visible);
                }
            } else {
                return; // require_auth already wrote 401
            }
            // CC7.2 evidence: record the scope-drop on this surface (#1634 compliance review).
            if (get_dropped > 0)
                (void)audit_log(req, "response.read", "denied", "Execution", instruction_id,
                                "scope_dropped=" + std::to_string(get_dropped) + " surface=get");

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
            // CDX-R4-02: authenticate BEFORE any store/body work (401 first).
            if (!require_auth(req, res))
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

            // K-04/CDX-R4-08: per-TARGET authorization -- NOT a global Tag:Write
            // gate. The old require_permission("Tag","Write") admitted a
            // service-scoped token on its ITServiceOwner grant with no target
            // check, so a service-A token could rewrite the `service` tag on a
            // service-B agent and escape its own #1788 dispatch confinement (and
            // it 403'd management-group-scoped operators). require_scoped_permission
            // enforces Tag:Write scoped to agent_id, the same gate the REST v1
            // twin (rest_api_v1.cpp) and MCP set_tag (mcp_server.cpp) use.
            if (!require_scoped_permission(req, res, "Tag", "Write", agent_id))
                return;

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
            // CDX-R4-02: authenticate BEFORE any store/body work (401 first).
            if (!require_auth(req, res))
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

            // K-04/CDX-R4-08: per-TARGET authorization (see /api/tags/set) --
            // a service-scoped token must not delete a tag on an out-of-scope
            // agent, and a group-scoped operator must be admitted on in-scope
            // targets. Same gate as the REST v1 twin and MCP delete_tag.
            if (!require_scoped_permission(req, res, "Tag", "Delete", agent_id))
                return;

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

        // Owner-checked read shared by every fragment mutation below: a DB
        // error is treated IDENTICALLY to "not found or not owned" — a
        // mutation (pin/unpin/delete) must never proceed on a degraded
        // ownership read (ADR-0036 fail-closed authoritative-read contract).
        // Collapses ResultSetStore::get's std::expected<optional<...>,...>
        // into a plain optional so every call site below is unchanged from
        // its pre-widening shape.
        auto rs_get_owned = [this](const std::string& id,
                                   const std::string& owner) -> std::optional<ResultSet> {
            if (!result_set_store_)
                return std::nullopt;
            auto row = result_set_store_->get(id);
            if (!row || !row->has_value() || (*row)->owner_principal != owner)
                return std::nullopt;
            return **row;
        };

        // Detail pane for one set (owner-checked).
        web_server_->Get(
            R"(/fragments/result-sets/(rs_[0-9a-f]+)/detail)",
            [this, rs_get_owned](const httplib::Request& req, httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session)
                    return;
                auto id = req.matches[1].str();
                auto row = rs_get_owned(id, session->username);
                if (!row) {
                    res.set_content(render_result_set_detail_empty(),
                                    "text/html; charset=utf-8");
                    return;
                }
                auto chain = result_set_store_->lineage(id, session->username);
                res.set_content(render_result_set_detail(*row, chain),
                                "text/html; charset=utf-8");
            });

        // Pin / unpin — return the refreshed detail and trigger a sidebar reload.
        auto rs_detail_after = [this, rs_get_owned](const std::string& id,
                                                    const std::string& owner,
                                                    httplib::Response& res) {
            auto row = rs_get_owned(id, owner);
            if (!row) {
                res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
                return;
            }
            auto chain = result_set_store_->lineage(id, owner);
            res.set_header("HX-Trigger", "resultSetsChanged");
            res.set_content(render_result_set_detail(*row, chain), "text/html; charset=utf-8");
        };

        web_server_->Post(
            R"(/fragments/result-sets/(rs_[0-9a-f]+)/pin)",
            [this, rs_detail_after, rs_get_owned](const httplib::Request& req,
                                                  httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session || !result_set_store_)
                    return;
                auto id = req.matches[1].str();
                auto row = rs_get_owned(id, session->username);
                if (!row) {
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
            [this, rs_detail_after, rs_get_owned](const httplib::Request& req,
                                                  httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session || !result_set_store_)
                    return;
                auto id = req.matches[1].str();
                auto row = rs_get_owned(id, session->username);
                if (!row) {
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
            [this, rs_get_owned](const httplib::Request& req, httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session || !result_set_store_)
                    return;
                auto id = req.matches[1].str();
                auto row = rs_get_owned(id, session->username);
                if (!row) {
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
            // Extracted to schedule_routes.cpp (H-01, #1806): the
            // Schedule:Write + Execution:Execute gate ordering needs direct
            // unit coverage that a bare inline lambda cannot get.
            handle_create_schedule(*auth_routes_, schedule_engine_.get(), req, res);
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
            // M-01 (#1806): owner-scoped delete — a Schedule:Delete grant
            // deletes only schedules the caller created, not the whole
            // fleet's. auth_routes_->resolve_session, not require_permission's
            // session (already consumed) — this call cannot fail auth since
            // require_permission above already proved a valid session exists.
            auto session = auth_routes_->resolve_session(req);
            auto user = session ? session->username : std::string();
            bool deleted = schedule_engine_->delete_schedule(id, user);
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
            // H-01 (#1806): re-enabling arms the schedule to fire unattended
            // through ScheduleRunner — the same fleet-wide-dispatch concern
            // as create, so it needs the same Execution:Execute gate.
            // Disabling only ever stops a schedule, so it stays gated on
            // Schedule:Write alone — an operator must be able to kill a
            // runaway schedule even without Execution:Execute.
            if (enabled && !require_permission(req, res, "Execution", "Execute"))
                return;

            // M-01 (#1806): owner-scoped enable/disable, same as delete above.
            auto session = auth_routes_->resolve_session(req);
            auto user = session ? session->username : std::string();
            bool changed = schedule_engine_->set_enabled(id, enabled, user);
            if (changed) {
                // L-04 (#1806): enable/disable had no audit trail at all.
                (void)audit_log(req, enabled ? "schedule.enable" : "schedule.disable", "success",
                                "schedule", id);
            }
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
                // A denied review is an access-control decision (e.g. the
                // self-approval segregation-of-duties block) — leave an audit
                // trace like the other denial paths in this file (governance
                // compliance CC6.1/CC6.3), and a greppable server-side line.
                (void)audit_log(req, "approval.approve", "denied", "approval", id,
                                result.error());
                spdlog::warn("approval approve denied: id={} reviewer={} reason={}",
                             log_safe(id), reviewer, log_safe(result.error(), 256));
                // htmx doesn't swap a non-2xx response, so without a trigger
                // the denial (e.g. the self-approval block) is a silent no-op
                // in the dashboard (#1821). HX-Trigger headers ARE processed
                // on error responses — surface the reason as a toast. dump()
                // uses `replace`: the error can echo the raw URL id, and the
                // default handler throws on invalid UTF-8 (governance UP-5).
                nlohmann::json trigger = {
                    {"showToast", {{"message", result.error()}, {"level", "error"}}}};
                res.set_header("HX-Trigger",
                               trigger.dump(-1, ' ', false,
                                            nlohmann::json::error_handler_t::replace));
                res.set_content(nlohmann::json({{"error", result.error()}})
                                    .dump(-1, ' ', false,
                                          nlohmann::json::error_handler_t::replace),
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
                // Same as the approve branch: audit the denial, log it, and
                // surface it as a toast (#1821) — htmx swallows non-2xx
                // bodies but processes HX-Trigger on them.
                (void)audit_log(req, "approval.reject", "denied", "approval", id,
                                result.error());
                spdlog::warn("approval reject denied: id={} reviewer={} reason={}",
                             log_safe(id), reviewer, log_safe(result.error(), 256));
                nlohmann::json trigger = {
                    {"showToast", {{"message", result.error()}, {"level", "error"}}}};
                res.set_header("HX-Trigger",
                               trigger.dump(-1, ' ', false,
                                            nlohmann::json::error_handler_t::replace));
                res.set_content(nlohmann::json({{"error", result.error()}})
                                    .dump(-1, ' ', false,
                                          nlohmann::json::error_handler_t::replace),
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
                // effective_role so an active JIT elevation also reveals the
                // authoring UI (the POST already gates on effective_role).
                bool can_author = (auth::effective_role(*session) == auth::Role::admin);

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
                        // d.id is operator-chosen since #402 (JSON create) /
                        // #1993 (YAML metadata.id). The store now bounds NEW
                        // ids to [A-Za-z0-9._-]{1,128}, but a row that predates
                        // that gate may hold arbitrary text — so encode it for
                        // the DOM at every interpolation (governance sec-M1).
                        // The Edit control carries the id in a data-attribute
                        // (html_escape makes it a safe attribute value) and
                        // reads it back via this.dataset.defId, NOT string-
                        // interpolated into the onclick JS: the browser
                        // entity-decodes an attribute BEFORE the JS parser runs,
                        // so a bare html_escape inside onclick="openEditor('…')"
                        // would still let a legacy id break out of the string
                        // and execute in the admin's session (Gate 8 SEC-1).
                        if (can_author) {
                            html += "<button class=\"btn btn-secondary btn-sm\" "
                                    "data-def-id=\"" +
                                    html_escape(d.id) +
                                    "\" onclick=\"openEditor(this.dataset.defId)\">Edit</button> ";
                        }
                        html += "<button class=\"btn btn-danger btn-sm\" "
                                "hx-delete=\"/api/instructions/" +
                                html_escape(d.id) +
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

            // Save shares one contract with /api/instructions/validate-yaml
            // (#1993): YAML that passes validation always carries what Save
            // needs, and a failing Save names the actual missing field
            // instead of a blanket "Missing required fields" for all three.
            auto errors = validate_yaml_source(yaml_source);
            if (!errors.empty()) {
                std::string html =
                    "<div class=\"alert alert-error\"><strong>Cannot save:</strong><ul>";
                for (const auto& e : errors)
                    html += "<li>" + html_escape(e) + "</li>";
                html += "</ul></div>";
                res.set_content(html, "text/html");
                return;
            }

            // Schema-aware extraction of the denormalized columns — accepts
            // both the canonical nested schema (metadata.id,
            // spec.execution.plugin/action — what the docs, validate-yaml,
            // and every bundled definition use) and the flat schema the New
            // Definition panel's structured form generates (metadata.name,
            // spec.plugin/action). The YAML source stays the verbatim source
            // of truth; absent optional fields get the same defaults the
            // bundled importer applies (embed_content.py::def_envelope).
            auto fields = instruction_yaml::parse_definition_yaml(yaml_source);

            InstructionDefinition def;
            def.name = fields.name;
            def.version = fields.version.empty() ? "1.0.0" : fields.version;
            def.plugin = fields.plugin;
            def.action = fields.action; // lowercased by the parser
            def.type = fields.type.empty() ? "question" : fields.type;
            def.description = fields.description;
            def.concurrency_mode = fields.concurrency.empty() ? "per-device" : fields.concurrency;
            def.approval_mode = fields.approval.empty() ? "auto" : fields.approval;
            def.yaml_source = yaml_source;
            def.created_by = session->username;
            def.enabled = true;

            // Toast + inline alert for every outcome. dump() uses the
            // `replace` error handler: failure messages can embed
            // operator-supplied ids, and the default handler would throw on
            // invalid UTF-8, degrading the feedback to a bare httplib 500
            // (governance cpp-S1 / UP-4).
            auto respond = [&](const std::string& msg, bool ok) {
                nlohmann::json trigger = {
                    {"showToast", {{"message", msg}, {"level", ok ? "success" : "error"}}}};
                res.set_header("HX-Trigger",
                               trigger.dump(-1, ' ', false,
                                            nlohmann::json::error_handler_t::replace));
                res.set_content("<div class=\"alert alert-" +
                                    std::string(ok ? "success" : "error") + "\">" +
                                    html_escape(msg) + "</div>",
                                "text/html");
            };

            if (!def_id.empty()) {
                // Route id is authoritative on update — but a yaml_source
                // self-declaring a DIFFERENT metadata.id would be stored
                // verbatim and fork the definition on any later re-import
                // (governance UP-8/cons-N1). Reject the divergence outright.
                if (!fields.id.empty() && fields.id != def_id) {
                    respond("YAML metadata.id '" + fields.id +
                                "' does not match the definition being edited ('" + def_id +
                                "') — correct or remove metadata.id",
                            false);
                    return;
                }
                def.id = def_id;
                auto result = instruction_store_->update_definition(def);
                if (!result) {
                    spdlog::warn("instruction yaml update failed: id={} error={}",
                                 log_safe(def_id), result.error());
                    respond("Update failed: " + result.error(), false);
                    return;
                }
                (void)audit_log(req, "instruction.update", "success", "InstructionDefinition",
                                def_id);
                emit_event("instruction.updated", req, {}, {{"instruction_id", def_id}});
                respond("Definition updated", true);
            } else {
                // A canonical definition names itself via metadata.id — honor
                // it (the store 409s on conflict), matching bundled-importer
                // semantics; without one the store generates an id.
                def.id = fields.id;
                auto result = instruction_store_->create_definition(def);
                if (!result) {
                    // #402 pattern (mirrors the JSON create route): strip the
                    // internal store↔route conflict token before it reaches
                    // the operator, map to 409 so scripted re-runs of the
                    // getting-started import see a real status, and leave a
                    // denied-audit trace for duplicate-id probing.
                    bool is_conflict = is_conflict_error(result.error());
                    spdlog::warn("instruction yaml create failed: id={} error={}",
                                 log_safe(def.id), result.error());
                    if (is_conflict) {
                        res.status = 409;
                        (void)audit_log(req, "instruction.create", "denied",
                                        "InstructionDefinition", def.id, "duplicate_id");
                        respond("Create failed: " +
                                    std::string(strip_conflict_prefix(result.error())),
                                false);
                    } else {
                        respond("Create failed: " + result.error(), false);
                    }
                    return;
                }
                (void)audit_log(req, "instruction.create", "success", "InstructionDefinition",
                                *result, def.name);
                emit_event("instruction.created", req,
                           {{"name", def.name}, {"plugin", def.plugin}, {"action", def.action},
                            {"type", def.type}},
                           {{"instruction_id", *result}});
                respond("Definition created", true);
            }
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
                            if (a.submitted_by == session->username) {
                                // Self-review is denied server-side
                                // (ApprovalManager: "reviewer cannot be the
                                // same as the submitter") — don't render
                                // buttons that can only silently fail (#1821).
                                html += "<span style=\"font-size:0.65rem;color:var(--muted)\">"
                                        "You submitted this — another reviewer must "
                                        "approve</span>";
                            } else {
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
            if (!tables) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"inventory store degraded"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& t : *tables) {
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
            if (!record.has_value()) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"inventory store degraded"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            if (!record->has_value()) {
                res.status = 404;
                res.set_content(
                    R"({"error":{"code":404,"message":"no inventory data found"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            const InventoryRecord& rec = **record;
            nlohmann::json data_obj;
            try {
                data_obj = nlohmann::json::parse(rec.data_json);
            } catch (...) {
                data_obj = rec.data_json;
            }
            res.set_content(nlohmann::json({{"agent_id", rec.agent_id},
                                            {"plugin", rec.plugin},
                                            {"data", data_obj},
                                            {"collected_at", rec.collected_at}})
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

            bool inventory_truncated = false;
            auto records = inventory_store_->query(q, &inventory_truncated);
            if (!records) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"inventory store degraded"},"meta":{"api_version":"v1"}})",
                    "application/json");
                return;
            }
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& r : *records) {
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
            res.set_content(nlohmann::json({{"results", arr},
                                            {"count", arr.size()},
                                            {"result_truncated_by_cap", inventory_truncated}})
                                .dump(),
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
                    // ADR-0042: get_visible_agents nullopt means the mgmt-store
                    // DEGRADED — return an EMPTY confined set (fail-closed: sees
                    // nothing), NOT nullopt here (which means "sees all fleet").
                    auto v = mgmt_group_store_->get_visible_agents(username);
                    if (!v)
                        return std::set<std::string>{};
                    return std::set<std::string>(v->begin(), v->end());
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
            // Background engines + legacy callers dispatch as SYSTEM (unfiltered):
            // exec_visible = nullopt. Operator surfaces that must confine call the
            // 7-param command_dispatch_confined_fn (below) instead. Both funnel
            // through the ONE dispatch_confined seam. broadcast_on_none=false: an
            // unnamed target here reaches nobody (#2500), never the fleet.
            return dispatch_confined(plugin, action, agent_ids, scope_expr, parameters,
                                     execution_id, /*exec_visible=*/std::nullopt,
                                     /*broadcast_on_none=*/false);
        };

        // #1788 / CDX-R7-02 / K-R7-02: the operator-facing confined entry.
        // Identical to command_dispatch_fn but carries the caller's
        // Execution:Execute visible set so dashboard + workflow dispatch narrow
        // to it, exactly as /api/command and MCP do. Same seam
        // (dispatch_confined), one extra parameter.
        auto command_dispatch_confined_fn =
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& agent_ids, const std::string& scope_expr,
                   const std::unordered_map<std::string, std::string>& parameters,
                   const std::string& execution_id,
                   const yuzu::server::authz::VisibleSet& exec_visible)
            -> std::pair<std::string, int> {
            return dispatch_confined(plugin, action, agent_ids, scope_expr, parameters,
                                     execution_id, exec_visible, /*broadcast_on_none=*/false);
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

        // App-perf B1->B2 roll-up thread (DEX app-perf-over-time). Re-rolls the
        // trailing window into B2 (idempotent) + prunes B2 beyond 180d, hourly.
        // Borrows app_perf_rollup_ + app_perf_fleet_store_, so it MUST be joined
        // before they / the pool are torn down (join sits with the policy-eval join
        // in stop()). Rolls once at start so B2 populates from existing B1 at boot.
        if (app_perf_rollup_ && app_perf_fleet_store_ && app_perf_fleet_store_->is_open()) {
            app_perf_rollup_thread_ = std::thread([this]() {
                spdlog::info("App-perf roll-up thread started (cadence=1h, B2 retention=180d)");
                bool first = true;
                while (!stop_requested_.load(std::memory_order_acquire)) {
                    if (!first) {
                        // ~1h in 5s steps so shutdown stays responsive.
                        for (int i = 0;
                             i < 720 && !stop_requested_.load(std::memory_order_acquire); ++i)
                            std::this_thread::sleep_for(std::chrono::seconds{5});
                        if (stop_requested_.load(std::memory_order_acquire))
                            break;
                    }
                    first = false;
                    // roll_window/prune touch PG; an exception escaping a std::thread
                    // entry calls std::terminate — catch, log, keep ticking.
                    try {
                        const std::int64_t now =
                            std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
                        app_perf_rollup_->roll_window(now);
                        const std::int64_t today = (now / 86400) * 86400;
                        app_perf_fleet_store_->prune(
                            today -
                            static_cast<std::int64_t>(AppPerfFleetStore::kRetentionDays) * 86400);
                    } catch (const std::exception& e) {
                        spdlog::error("app_perf_rollup: tick threw ({}) — thread continuing",
                                      e.what());
                    } catch (...) {
                        spdlog::error("app_perf_rollup: tick threw unknown exception — continuing");
                    }
                }
            });
        }
        // PreflightRunner — /auto re-dispatch-on-reconnect + window lifecycle.
        // Same dispatch lambda as operator commands; per-check execution_ids union
        // re-dispatches via query_by_execution. Joined BEFORE the stores in stop().
        metrics_.describe("yuzu_preflight_tick_errors_total",
                          "Pre-flight runner tick() exceptions caught (alertable on sustained rate)",
                          "counter");
        preflight_runner_ = std::make_unique<PreflightRunner>(PreflightRunner::Deps{
            .run_store = preflight_run_store_.get(),
            .response_store = response_store_.get(),
            .dispatch_fn = command_dispatch_fn,
            .now_ms_fn = {},
            .retention_days = 14,
        });
        preflight_runner_thread_ = std::thread([this]() {
            spdlog::info("Pre-flight runner thread started (cadence=60s, retention=14d)");
            while (!stop_requested_.load(std::memory_order_acquire)) {
                for (int i = 0; i < 12 && !stop_requested_.load(std::memory_order_acquire); ++i)
                    std::this_thread::sleep_for(std::chrono::seconds{5});
                if (stop_requested_.load(std::memory_order_acquire))
                    break;
                if (preflight_runner_) {
                    // tick() touches JSON, PG and gRPC dispatch — any can throw; an
                    // escaping exception would std::terminate the process, so a bad
                    // run must not take it down. Catch, log, keep ticking.
                    try {
                        preflight_runner_->tick();
                    } catch (const std::exception& e) {
                        metrics_.counter("yuzu_preflight_tick_errors_total").increment();
                        spdlog::error("preflight_runner: tick threw ({}) — thread continuing",
                                      e.what());
                    } catch (...) {
                        metrics_.counter("yuzu_preflight_tick_errors_total").increment();
                        spdlog::error("preflight_runner: tick threw unknown exception — continuing");
                    }
                }
                // 14-day retention for deployment runs. DeploymentRunStore has no
                // background runner of its own in slice 1, so the prune piggy-backs
                // this thread (mirrors the preflight prune cadence) — without it the
                // documented retention never runs and deployment_device grows
                // unbounded (#governance H2/CAP-1).
                if (deployment_run_store_ && deployment_run_store_->is_open()) {
                    try {
                        const auto cutoff =
                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count() -
                            14LL * 24 * 60 * 60 * 1000;
                        deployment_run_store_->prune_older_than(cutoff);
                    } catch (const std::exception& e) {
                        spdlog::error("deployment prune threw ({}) — thread continuing", e.what());
                    } catch (...) {
                        spdlog::error("deployment prune threw unknown exception — continuing");
                    }
                }
            }
        });

        // ScheduleRunner (#1191) — drives recurring-instruction schedules.
        // ScheduleEngine::evaluate_due/advance_schedule had no production
        // caller: schedules persisted and listed but never fired. Fires travel
        // the same dispatch lambda as operator commands with tracked
        // create-before-dispatch execution rows; approval-gated fires wait on
        // the approvals queue (see schedule_runner.hpp). Joined BEFORE the
        // stores in stop().
        metrics_.describe("yuzu_schedule_fires_total",
                          "Scheduled instruction occurrences dispatched successfully", "counter");
        metrics_.describe("yuzu_schedule_fire_failures_total",
                          "Scheduled occurrences skipped or failed (unknown/disabled definition, "
                          "dispatch failure, no agents in scope, approval submit failure)",
                          "counter");
        metrics_.describe("yuzu_schedule_approvals_submitted_total",
                          "Approval tickets submitted by the schedule runner for approval-gated "
                          "occurrences",
                          "counter");
        metrics_.describe("yuzu_schedule_tick_errors_total",
                          "Schedule runner tick() exceptions caught (alertable on sustained rate)",
                          "counter");
        schedule_runner_ = std::make_unique<ScheduleRunner>(ScheduleRunner::Deps{
            .schedule_engine = schedule_engine_.get(),
            .instruction_store = instruction_store_.get(),
            .execution_tracker = execution_tracker_.get(),
            .approval_manager = approval_manager_.get(),
            .audit_store = audit_store_.get(),
            .metrics = &metrics_,
            .dispatch_fn = command_dispatch_fn,
        });
        schedule_tick_thread_ = std::thread([this]() {
            spdlog::info("Schedule runner thread started (cadence=30s)");
            while (!stop_requested_.load(std::memory_order_acquire)) {
                for (int i = 0; i < 6 && !stop_requested_.load(std::memory_order_acquire); ++i)
                    std::this_thread::sleep_for(std::chrono::seconds{5});
                if (stop_requested_.load(std::memory_order_acquire))
                    break;
                if (schedule_runner_) {
                    // tick() touches SQLite and gRPC dispatch — either can
                    // throw, and an exception escaping a std::thread entry
                    // calls std::terminate, so one bad schedule must not take
                    // the process. Catch, log, keep ticking.
                    try {
                        schedule_runner_->tick();
                    } catch (const std::exception& e) {
                        metrics_.counter("yuzu_schedule_tick_errors_total").increment();
                        spdlog::error("schedule_runner: tick threw ({}) — thread continuing",
                                      e.what());
                    } catch (...) {
                        metrics_.counter("yuzu_schedule_tick_errors_total").increment();
                        spdlog::error("schedule_runner: tick threw unknown exception — continuing");
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
            policy_evaluator_.get(), &metrics_); // #2500 targeting-refusal counter

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

        // App-perf-over-time providers (F2b) — ONE bundle threaded through the
        // dashboard (DexRoutes), the REST surface (RestApiV1) and the MCP tools, so
        // all three read the SAME stores. nullopt from any seam = an honest degrade
        // (the read surfaces map it to a 503 / "unavailable" note, never a silent
        // empty). The fleet + picker seams read B2; the per-device drill reads B1
        // (audited at the route); the group roll-up resolves members then aggregates
        // B1 — two bounded single-store reads composed, never a held cross-store
        // lease (ADR-0012 §1).
        AppPerfProviders app_perf_providers;
        app_perf_providers.fleet =
            [this](std::string_view app, std::string_view version)
            -> std::optional<std::vector<AppPerfFleetRow>> {
            if (!app_perf_fleet_store_)
                return std::nullopt;
            return app_perf_fleet_store_->get_app_fleet_perf(app, version);
        };
        app_perf_providers.apps =
            [this](bool& truncated) -> std::optional<std::vector<AppPerfAppSummary>> {
            if (!app_perf_fleet_store_)
                return std::nullopt;
            return app_perf_fleet_store_->list_apps(truncated);
        };
        app_perf_providers.device =
            [this](std::string_view agent_id) -> std::optional<std::vector<AppPerfDailyRow>> {
            if (!app_perf_daily_store_)
                return std::nullopt;
            return app_perf_daily_store_->get_agent_app_perf(agent_id);
        };
        app_perf_providers.group =
            [this](std::string_view group_id, std::string_view app,
                   std::string_view version) -> std::optional<std::vector<AppPerfFleetRow>> {
            if (!app_perf_group_reader_ || !mgmt_group_store_)
                return std::nullopt;
            // Resolve members (one bounded read, lease released), THEN aggregate B1
            // (a second bounded read) — never a lease held across the other (ADR-0012
            // §1). An empty/unknown group → empty member list → empty 200, not a leak.
            const auto members = mgmt_group_store_->get_members(std::string(group_id));
            std::vector<std::string> agent_ids;
            agent_ids.reserve(members.size());
            for (const auto& m : members)
                agent_ids.push_back(m.agent_id);
            return app_perf_group_reader_->get_group_trend(agent_ids, app, version);
        };
        app_perf_providers.cohort =
            [this](std::string_view group_id, std::string_view app, std::string_view baseline,
                   std::string_view candidate, int window_days) -> std::optional<CohortRead> {
            if (!app_perf_cohort_reader_ || !mgmt_group_store_)
                return std::nullopt;
            // Resolve members (one bounded read, lease released), THEN read their raw
            // B1 rows (a second bounded read) — never a lease held across the other
            // (ADR-0012 §1). The /auto VERIFY compare engine pairs these per machine.
            const auto members = mgmt_group_store_->get_members(std::string(group_id));
            std::vector<std::string> agent_ids;
            agent_ids.reserve(members.size());
            for (const auto& m : members)
                agent_ids.push_back(m.agent_id);
            CohortRead out;
            out.member_count = static_cast<std::int64_t>(agent_ids.size());
            if (agent_ids.empty())
                return out; // empty/unknown group → member_count 0, no rows (not a degrade)
            bool truncated = false;
            auto rows = app_perf_cohort_reader_->get_cohort_rows(agent_ids, app, baseline, candidate,
                                                                 window_days, truncated);
            if (!rows)
                return std::nullopt; // AUTHORITATIVE degrade (the row read failed)
            out.rows = std::move(*rows);
            out.truncated = truncated;
            return out;
        };
        // COPY the cohort provider (std::function is copyable) so the /auto VERIFY
        // routes keep a live seam even after app_perf_providers is moved into the
        // REST + MCP registrars below.
        AppPerfCohortFn verify_cohort_fn = app_perf_providers.cohort;
        // The dashboard scope-selector's group list (id + name only). NO per-group
        // member count: that would be an N+1 get_members() over the store on every
        // render (UP-7); the selector needs names, not counts.
        DexRoutes::GroupListFn dex_group_list_fn = [this]() -> std::vector<DexGroupOption> {
            std::vector<DexGroupOption> out;
            if (!mgmt_group_store_)
                return out;
            for (const auto& g : mgmt_group_store_->list_groups())
                out.push_back({g.id, g.name});
            return out;
        };

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
                        // Per-OS online denominators (#1746) — same coverage-honest
                        // count as windows_online, so the Catalogue's single-OS
                        // filter can score a family against THAT OS's own fleet.
                        if (os.starts_with("lin"))
                            ++f.linux_online;
                        if (os.starts_with("darwin") || os.starts_with("macos"))
                            ++f.macos_online; // prefix, like win/lin — keep in
                                              // step with the store's write canon
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
            [this](const std::string& command_id,
                   const std::string& agent_id) -> std::vector<DexAgentResponse> {
                std::vector<DexAgentResponse> out;
                if (!response_store_)
                    return out;
                ResponseQuery q;
                q.agent_id = agent_id; // #1634: scope the poll read AT THE STORE SEAM
                for (const auto& r : response_store_->query(command_id, q))
                    out.push_back({r.agent_id, r.status, r.output, r.error_detail});
                return out;
            },
            // F2a: the shared fleet perf snapshot provider (defined above).
            dex_perf_fn,
            // Per-device scope gate (same require_scoped_permission the /device routes
            // use) + the visible-agent set resolver — so the per-device DEX drills are
            // scoped and the device-id lists never enumerate out-of-scope agents.
            scoped_perm_fn, visible_set_fn,
            // F2b app-perf-over-time providers + the scope-selector group list.
            app_perf_providers, dex_group_list_fn);

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
            // "Get live info" dispatches real read-only plugin instructions through the
            // shared chokepoint — the live-snapshot cards (processes/list_tree +
            // network_diag/connections, services/list, users/logged_on,
            // network_config/{ip_addresses,arp,dns_cache}, network_diag/listening +
            // connections, tar/status) plus os_info/uptime for the KPI. DELIBERATELY an
            // UNTRACKED dispatch (empty execution_id → no ExecutionTracker row, not in
            // the executions drawer): the snapshot auto-fires one query per card when an
            // operator clicks Get live info, so tracking would flood the drawer with a
            // burst of executions per view. This matches the already-shipped DEX device-perf
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
            [this](const std::string& command_id,
                   const std::string& agent_id) -> std::vector<DexAgentResponse> {
                std::vector<DexAgentResponse> out;
                if (!response_store_)
                    return out;
                ResponseQuery q;
                q.agent_id = agent_id; // #1634: scope the poll read AT THE STORE SEAM
                for (const auto& r : response_store_->query(command_id, q))
                    out.push_back({r.agent_id, r.status, r.output, r.error_detail});
                return out;
            },
            audit_fn);

        // InventoryRoutes — /inventory: the SOFTWARE inventory list (fleet catalogue +
        // installs-per-version drill + find-by-name) over SoftwareInventoryStore, gated on
        // the GLOBAL Inventory:Read (the catalogue/find aggregates are NOT mgmt-group
        // scoped — ADR-0017 confinement inert under the global gate, caveated in the UI;
        // FIND applies the SAME per-row Inventory:Read drop filter the REST sibling does).
        // Plus a THIN device-CI tab sourced from the persisted, offline-survivable
        // endpoint_state store (so offline devices still appear) joined to the registry's
        // online set; the per-device software drill gates on scoped_perm_fn(Inventory,Read,id)
        // and audits the access (set-and-proceed — machine-scope data). Reuses the shared
        // auth/perm/scoped-perm/audit closures + the SAME check_scoped_permission predicate
        // the REST /api/v1/inventory/software route uses (cross-surface parity).
        auto inv_human_age = [](std::int64_t ms) -> std::string {
            if (ms < 0)
                ms = 0;
            const std::int64_t s = ms / 1000;
            if (s < 90)
                return "just now";
            const std::int64_t m = s / 60;
            if (m < 90)
                return std::to_string(m) + "m ago";
            const std::int64_t h = m / 60;
            if (h < 48)
                return std::to_string(h) + "h ago";
            return std::to_string(h / 24) + "d ago";
        };
        auto inv_devices_fn = [this, visible_set_fn,
                               inv_human_age](const std::string& username)
            -> InventoryDevicesResult {
            InventoryDevicesResult result;
            auto& out = result.rows;
            if (!offline_endpoint_store_) {
                result.ci_degraded = true; // no roster → no CI enrichment attempted either
                return result;
            }
            // Persisted endpoints within a 30-day window — OFFLINE-INCLUSIVE (the whole
            // point of the device tab: readable when a device is offline). Aged-out hosts
            // beyond the window are withheld so the list doesn't accrete dead hosts forever.
            auto eps = offline_endpoint_store_->query_stale_within(std::chrono::hours(24 * 30));
            // currently-connected agents (live registry). all_ids() copies only the ids
            // under the registry lock — NOT to_json_obj()'s full 5-field-per-agent JSON
            // serialisation under the heartbeat/dispatch hot-path mutex (gov perf-S2).
            // unordered_set: O(1) membership over up to fleet-size ids (gov perf-N2).
            auto online_ids = registry_.all_ids();
            std::unordered_set<std::string> online(online_ids.begin(), online_ids.end());
            const auto visible = visible_set_fn(username); // nullopt = sees all (global read)
            const std::int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count();
            for (const auto& e : eps) {
                if (visible && !visible->count(e.agent_id))
                    continue; // out of the operator's management scope
                InventoryDeviceRow r;
                r.agent_id = e.agent_id;
                r.hostname = e.hostname;
                r.os = e.os;
                r.online = online.count(e.agent_id) > 0;
                const std::int64_t age_ms = now_ms - e.last_heartbeat_ms;
                r.stale = age_ms > (2LL * 24 * 60 * 60 * 1000); // matches the inventory stale window
                r.last_seen = r.online ? std::string("now") : inv_human_age(age_ms);
                out.push_back(std::move(r));
            }
            // Device-CI enrichment (PR2): one list_device_ci(0) read — `0` means "uncapped,
            // clamped to DeviceInventoryStore's kListRowCap (100k)" per that store's own
            // limit-clamp contract, not "zero rows" — (symmetric with the full
            // offline_endpoint_store_ materialize above), joined by agent_id via the pure
            // attach_device_ci (inventory_ci_join.cpp). `out` is ALREADY the
            // visible-confined roster (the loop above already dropped out-of-scope
            // agents) — attach_device_ci only ever looks up by an agent_id already in
            // `out`, so a CI row for an out-of-scope agent riding along in the same read
            // is never attached, never rendered. A degrade (nullopt) leaves CI columns
            // blank — the roster itself is still shown (this list is best-effort, unlike
            // the Software tab's authoritative reads; see the existing empty-roster note).
            // KNOWN FOLLOW-UP (#1783 — gov Gate 3 performance + architect + Gate 5 chaos
            // review): this reads the WHOLE fleet's CI on every render regardless of how
            // few devices are visible, unlike the Software tab's hourly rollup
            // (software_catalog_rollup.cpp) which exists specifically to avoid this
            // read-cadence-vs-write-cadence mismatch for daily-synced data. Deferred rather
            // than fixed here to keep this PR scoped to dashboard-read enrichment.
            //
            // `result.ci_degraded` (#1785 review HIGH-1) tells the route's audit whether
            // the CI columns above are genuinely enriched or blank because this join
            // failed/was unwired — an unwired store is treated the same as a live failure
            // (mirrors AgentCiFn's documented contract for the per-device drill).
            if (device_inventory_store_) {
                auto ci_list = device_inventory_store_->list_device_ci(0);
                if (ci_list) {
                    std::unordered_map<std::string, DeviceCiRecord> ci_by_agent;
                    ci_by_agent.reserve(ci_list->size());
                    for (auto& rec : *ci_list)
                        // Safe: pair's members initialize in declaration order (`first`
                        // before `second`), so the key copies from `rec.agent_id` before
                        // `std::move(rec)` constructs `second` and leaves `rec` (incl. its
                        // own .agent_id member) moved-from. Don't read the map VALUE's own
                        // .agent_id after this, though — it's redundant with (and no longer
                        // matches) the key; attach_device_ci never does (gov Gate 3
                        // cpp-expert review).
                        ci_by_agent.emplace(rec.agent_id, std::move(rec));
                    attach_device_ci(out, ci_by_agent);
                } else {
                    result.ci_degraded = true;
                }
            } else {
                result.ci_degraded = true;
            }
            return result;
        };
        inventory_routes_ = std::make_unique<InventoryRoutes>();
        inventory_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, scoped_perm_fn,
            [this](const SoftwareCatalogQuery& q)
                -> std::optional<std::vector<SoftwareCatalogRow>> {
                if (!software_inventory_store_)
                    return std::nullopt;
                return software_inventory_store_->software_catalog(q);
            },
            [this]() -> std::optional<CatalogRollupMeta> {
                if (!software_inventory_store_)
                    return std::nullopt;
                return software_inventory_store_->catalog_rollup_meta();
            },
            [this](const std::string& name,
                   int limit) -> std::optional<std::vector<SoftwareVersionCount>> {
                if (!software_inventory_store_)
                    return std::nullopt;
                return software_inventory_store_->software_versions(name, limit);
            },
            [this](const SoftwareFleetQuery& q) -> std::optional<std::vector<SoftwareFleetRow>> {
                if (!software_inventory_store_)
                    return std::nullopt;
                return software_inventory_store_->query_software(q);
            },
            [this](const std::string& id) -> std::optional<std::vector<SoftwareEntry>> {
                if (!software_inventory_store_)
                    return std::nullopt;
                return software_inventory_store_->get_agent_software(id);
            },
            inv_devices_fn,
            // FIND per-row Inventory:Read management-group scope predicate — the SAME
            // check_scoped_permission chokepoint the REST route + MCP tool use.
            // FAIL-CLOSED on a corrupt/load-failed rbac.db (#1717): gates on
            // rbac_enforcement_in_effect, NOT raw !is_rbac_enabled() (which fails OPEN — a
            // null db reads as "RBAC off → no filter" → cross-operator IDOR). Mirrors
            // response_agent_in_scope (server.cpp); the REST/MCP siblings still carry the raw
            // form pending the #1717 global-gate fix, but each new list-read takes the safe
            // primitive now (ADR-0017 ship-now, decision-independent hardening).
            [this](const std::string& username, const std::string& agent_id) -> bool {
                if (!rbac_enforcement_in_effect(rbac_store_.get()))
                    return true; // loaded & explicitly disabled → legacy-open
                return rbac_store_ && rbac_store_->check_scoped_permission(
                                          username, "Inventory", "Read", agent_id,
                                          mgmt_group_store_.get());
            },
            // Freshness KPI: current stale count (nullopt on degrade → "—" in the UI).
            // SAME 2-missed-cycles window as the metrics sweep.
            [this]() -> std::optional<std::int64_t> {
                if (!software_inventory_store_)
                    return std::nullopt;
                constexpr std::int64_t kWin = 2 * 24 * 60 * 60;
                const std::int64_t cutoff = std::chrono::duration_cast<std::chrono::seconds>(
                                                std::chrono::system_clock::now().time_since_epoch())
                                                .count() -
                                            kWin;
                return software_inventory_store_->count_stale_agents(cutoff);
            },
            audit_fn,
            // Per-device CI record (drill panel, post scoped_perm_fn gate). Mirrors
            // agent_sw_fn_'s "unwired closure" fallback: not applicable here since this
            // closure is always wired when device_inventory_store_ exists, and returns a
            // live kDegraded when it doesn't (the store itself failed to construct/open).
            // Appended after audit_fn (rather than inserted mid-signature) to match the
            // DeviceRoutes/DexRoutes convention of growing register_routes by appending
            // new closures with a `= {}` default (gov Gate 3 architect review).
            [this](const std::string& id)
                -> std::expected<std::optional<DeviceCiRecord>, CiReadError> {
                if (!device_inventory_store_)
                    return std::unexpected(CiReadError::kDegraded);
                return device_inventory_store_->get_device_ci(id);
            });

        // SleRoutes — /api/v1/sle/* SLE read surface (ADR-0024, PR1a). Gated on the
        // NEW SoftwareLicensing securable via the FAIL-CLOSED enforcement primitive
        // (roadmap G-1 / Decision 10). The shared require_permission /
        // require_scoped_permission use the is_rbac_enabled() shape, which on a
        // corrupt / load-failed rbac.db (is_rbac_enabled()==false) falls through to a
        // legacy-open Read — the #1717 fail-open. rbac_enforcement_in_effect() is true
        // for a null / !is_open() store as well as an enabled one, so this guard only
        // permits the legacy-open path when the store is loaded AND explicitly disabled;
        // a null/corrupt store is REFUSED (503), never served a legacy-open (and, for
        // the drill, UNSCOPED) Read of licence data incl. user_ref PII. This closes
        // #1717 for the SLE gates now, without waiting on the global-gate fix.
        auto sle_gate_usable = [this](const httplib::Request& req, httplib::Response& res) -> bool {
            if (rbac_enforcement_in_effect(rbac_store_.get()) &&
                !(rbac_store_ && rbac_store_->is_open())) {
                // Resolve auth first so an unauthenticated caller sees 401 (and never
                // learns the store state) before the fail-closed 503.
                if (require_auth(req, res)) {
                    res.status = 503;
                    // Carry the route's REAL correlation id (already stamped on the
                    // response as X-Correlation-Id by the SLE handler before the gate
                    // ran) into the A4 body, matching every other SLE 503 — never a
                    // hardcoded empty id. The cid is the grep-safe `req-<hex>-<hex>`
                    // shape (no JSON metacharacters), so plain interpolation is safe;
                    // an unset header falls back to "" (the prior behaviour).
                    const std::string cid = res.get_header_value("X-Correlation-Id");
                    res.set_content(
                        std::string(
                            R"({"error":{"code":503,"message":"authorization subsystem )"
                            R"(unavailable","correlation_id":")") +
                            cid +
                            R"(","retry_after_ms":5000},"meta":{"api_version":"v1"}})",
                        "application/json");
                }
                return false;
            }
            return true;
        };
        auto sle_scoped_perm_fn = [this, sle_gate_usable](
                                      const httplib::Request& req, httplib::Response& res,
                                      const std::string& type, const std::string& op,
                                      const std::string& agent_id) -> bool {
            if (!sle_gate_usable(req, res))
                return false;
            return require_scoped_permission(req, res, type, op, agent_id);
        };
        sle_routes_ = std::make_unique<SleRoutes>();
        // Per ADR-0024 "Placement under ADR-1005", only the discovery mechanism is
        // in-server: the raw per-agent drill (GET) and the audited durable-erasure
        // trigger (DELETE). The posture/compliance reads and the fan-out list are the
        // SAM UCE module's interpretation surface, not built here. The discovery
        // read's machine-surface twin is the `query_software_licenses` MCP tool
        // (mcp_server.cpp), per ADR-1005 Decision 1.
        sle_routes_->register_routes(
            *web_server_, sle_scoped_perm_fn,
            // Single-agent drill — REAL detected-licence data. nullopt on degrade → 503.
            [this](const std::string& agent_id) -> std::optional<std::vector<AgentLicenseRow>> {
                if (!software_licensing_store_)
                    return std::nullopt;
                return software_licensing_store_->agent_licenses(agent_id);
            },
            // Erasure cascade — the DELETE route's production caller (Decision 11):
            // fans delete_agent across every registered per-agent store.
            [this](const std::string& agent_id) -> DecommissionResult {
                return decommission_agent(agent_id);
            },
            audit_fn);

        // PreflightRoutes — /auto pre-flight page. A config section (per-check
        // params + thresholds) runs the live checks (app version / os_version /
        // os_arch / free-disk / pending-reboot) across the operator-VISIBLE devices
        // in a chosen management group (optionally narrowed by OS family), applies
        // the thresholds server-side, and groups the result BY DEVICE (Pass / Failed
        // / Warn-only / Incomplete). Reuses DeviceRoutes' scoped device provider
        // (devices_fn) + the SAME untracked dispatch (execution_id="" → not in the
        // executions drawer, like device live-info / DEX-perf reads) + a narrow
        // all-agents ResponseStore seam (query by command_id, no agent filter — the
        // grid only counts the pinned visible∩group devices, so an extra agent
        // in the result is ignored). Machine-health facts, not behavioural PII →
        // operational `preflight.run` audit (set-and-proceed).
        preflight_routes_ = std::make_unique<PreflightRoutes>();
        preflight_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, devices_fn,
            [this]() -> std::vector<std::pair<std::string, std::string>> {
                std::vector<std::pair<std::string, std::string>> out;
                if (mgmt_group_store_)
                    for (const auto& g : mgmt_group_store_->list_groups())
                        out.emplace_back(g.id, g.name);
                return out;
            },
            [this](const std::string& group_id) -> std::vector<std::string> {
                std::vector<std::string> out;
                if (mgmt_group_store_)
                    for (const auto& m : mgmt_group_store_->get_members(group_id))
                        out.push_back(m.agent_id);
                return out;
            },
            // 6-param dispatch: execution_id carried so re-dispatched checks union
            // via query_by_execution (the runner reuses the same per-check ids).
            command_dispatch_fn,
            // Collect: per-check query_by_execution + latest_per_agent (LIVE render
            // of a running run). NOT under any PreflightRunStore lease.
            [this](const std::string& run_id,
                   const std::vector<std::pair<std::string, std::string>>& applicable)
                -> std::vector<preflight::PreflightCheckResponses> {
                if (!response_store_)
                    return {};
                return preflight::collect_check_responses(*response_store_, run_id, applicable);
            },
            audit_fn, preflight_run_store_.get());

        // VerifyRoutes — /auto Stage 3 VERIFY: the cohort-paired before/after
        // app-perf evidence (UAT non-functional). Reads the shipped B1 store via the
        // COPIED cohort provider; the pure compare engine pairs each machine. The
        // aggregate read is an operational `dex.app_perf.compare` audit (set-and-
        // proceed — the accountability that stands in for the absent floor); the
        // per-machine drill is the audited PII surface. EVIDENTIAL only — no verdict,
        // NO cohort floor (real canaries are 2-3 devices). Shares the /auto auth +
        // group list with PreflightRoutes.
        verify_routes_ = std::make_unique<VerifyRoutes>();
        verify_routes_->register_routes(
            *web_server_, auth_fn, perm_fn,
            [this]() -> std::vector<std::pair<std::string, std::string>> {
                std::vector<std::pair<std::string, std::string>> out;
                if (mgmt_group_store_)
                    for (const auto& g : mgmt_group_store_->list_groups())
                        out.emplace_back(g.id, g.name);
                return out;
            },
            std::move(verify_cohort_fn), audit_fn);

        // DeploymentRoutes — the /auto DEPLOY stage. As soon as a pre-flight run has
        // a go-cohort (mid-run, no completion required), stages + executes an
        // installer (content_dist) on the cleared-so-far devices, tracking the
        // per-device stage→execute state machine. Reuses the scoped
        // device provider (devices_fn) for the live re-authorization the MUTATING
        // execute step requires, the SAME 6-param untracked dispatch (execution_id
        // "deployment-<id>-{stage,exec}" → skipped by notify_exec_tracker, like
        // preflight-), and a narrow ResponseStore poll seam (query_by_execution +
        // latest_per_agent). The cohort is read from preflight_run_store_.
        deployment_routes_ = std::make_unique<DeploymentRoutes>();
        deployment_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, devices_fn, command_dispatch_fn,
            // Poll seam: execution_id → best (status, output) per agent. Same
            // scoring as the pre-flight collect (terminal beats running, then
            // non-empty output, then later arrival).
            [this](const std::string& execution_id)
                -> std::unordered_map<std::string, deployment::AgentResponse> {
                if (!response_store_)
                    return {};
                ResponseQuery q;
                q.limit = 50000; // > cohort cap (20000) with headroom; keyset paging is a follow-up
                return deployment::best_response_per_agent(
                    response_store_->query_by_execution(execution_id, q));
            },
            audit_fn, preflight_run_store_.get(), deployment_run_store_.get());

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
            [this](const std::string& command_id,
                   const std::string& agent_id) -> std::vector<DexAgentResponse> {
                std::vector<DexAgentResponse> out;
                if (!response_store_)
                    return out;
                ResponseQuery q;
                q.agent_id = agent_id; // #1634: scope the poll read AT THE STORE SEAM
                for (const auto& r : response_store_->query(command_id, q))
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
        // #2537: declare the external origins BEFORE register_routes — the
        // handlers capture `this` at registration and read the member per
        // request, so setting it afterwards would never reach a live route.
        dashboard_routes_->set_csrf_trusted_origins(cfg_.csrf_trusted_origins);
        dashboard_routes_->register_routes(
            *web_server_, auth_fn, perm_fn, audit_fn, response_store_.get(),
            mgmt_group_store_.get(), &registry_, tag_store_.get(), &event_bus_,
            [this]() -> std::string { return registry_.to_json(); },
            // DispatchFn — the dashboard execute surface, now routed through the
            // shared dispatch_confined seam exactly as /api/command and MCP are.
            //
            // CDX-R7-02: carries the operator's Execution:Execute visible set
            // (`exec_visible`, derived per-request by the ExecVisibleFn below)
            // and narrows every arm to it — a management group / scope / id-list
            // / broadcast is a targeting mechanism, never an authz exemption
            // (#1788). execution_id is empty (dashboard is the legacy untracked
            // UI path). broadcast_on_none=true preserves the legacy UI contract
            // that an OMITTED `scope` means the whole fleet. It is NOT about
            // `__all__`: dashboard_routes passes that through by name (the
            // Broadcast arm), and refuses a supplied-but-empty `scope=`, so None
            // reaches here only when no targeting argument was supplied at all.
            [this](const std::string& plugin, const std::string& action,
                   const std::vector<std::string>& agent_ids, const std::string& scope_expr,
                   const std::unordered_map<std::string, std::string>& parameters,
                   const yuzu::server::authz::VisibleSet& exec_visible)
                -> std::pair<std::string, int> {
                auto [command_id, sent] = dispatch_confined(plugin, action, agent_ids, scope_expr,
                                                            parameters, /*execution_id=*/std::string{},
                                                            exec_visible, /*broadcast_on_none=*/true);

                if (sent > 0) {
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
            // ExecVisibleFn — CDX-R7-02: resolve the caller's Execution:Execute
            // visible set from the request. The dashboard execute handlers gate
            // via perm_fn and hold no Session at the dispatch site, so resolve it
            // here from a throwaway Response (never written back). A session that
            // cannot be resolved yields a present-EMPTY set — fail CLOSED, deny
            // all — never nullopt.
            [this](const httplib::Request& req) -> yuzu::server::authz::VisibleSet {
                httplib::Response throwaway;
                if (auto s = require_auth(req, throwaway))
                    return derive_exec_visible(*s);
                return std::unordered_set<std::string>{};
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
            // Resolve from_result_set: aliases for the estimate too (PR-E). This
            // is a pure preview/telemetry surface (no grant/target/enforce), so
            // a degrade renders as an honest "0 matched" rather than aborting
            // the whole page (ADR-0036 fail-closed contract §"pure render
            // callers may degrade") — it never feeds a dispatch decision.
            auto resolved = resolve_scope_aliases(expression, principal, result_set_store_.get());
            if (!resolved)
                return {0, registry_.agent_count()};
            auto parsed = yuzu::scope::parse(*resolved);
            if (!parsed)
                return {0, registry_.agent_count()};
            auto matched =
                registry_.evaluate_scope(*parsed, tag_store_.get(), custom_properties_store_.get(),
                                         result_set_store_.get(), principal);
            if (!matched)
                return {0, registry_.agent_count()};
            return {matched->size(), registry_.agent_count()};
        };
        wf_deps.workflow_engine = workflow_engine_.get();
        wf_deps.execution_tracker = execution_tracker_.get();
        wf_deps.schedule_engine = schedule_engine_.get();
        wf_deps.product_pack_store = product_pack_store_.get();
        wf_deps.instruction_store = instruction_store_.get();
        wf_deps.policy_store = policy_store_.get();
        // K-R7-02: workflow + instruction dispatch is an OPERATOR surface, so it
        // routes through the CONFINED 7-param sibling (carries the caller's
        // Execution:Execute visible set), not the system 6-param command_dispatch_fn.
        // Both funnel through the ONE dispatch_confined seam.
        wf_deps.command_dispatch_fn = command_dispatch_confined_fn;
        wf_deps.exec_visible_fn =
            [this](const httplib::Request& req) -> yuzu::server::authz::VisibleSet {
            // Resolve the session from a throwaway Response (never written back);
            // an unresolved session yields a present-EMPTY set (fail CLOSED).
            httplib::Response throwaway;
            if (auto s = require_auth(req, throwaway))
                return derive_exec_visible(*s);
            return std::unordered_set<std::string>{};
        };
        wf_deps.approval_manager = approval_manager_.get();
        wf_deps.response_store = response_store_.get();
        // PR 3 — SSE event bus for live execution updates. Server owns
        // the bus; ExecutionTracker publishes onto it; SSE handler
        // subscribes per-connection.
        wf_deps.execution_event_bus = execution_event_bus_.get();
        wf_deps.stream_budget = stream_budget_.get(); // ADR-0034: one budget, every surface
        wf_deps.metrics = &metrics_;                  // #2500 targeting-refusal counter
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
        // #2537: same ordering rule as DashboardRoutes above — register_routes
        // copies the list into its handler captures, so it must be set first.
        ca_routes_->set_csrf_trusted_origins(cfg_.csrf_trusted_origins);
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

        // -- #2395: KEK rotation REST surface (/api/v1/secrets/kek/*) -------------
        // The crypto + Postgres access is injected as the KekOps seam so
        // kek_routes.{hpp,cpp} links neither (kek_routes.hpp header comment).
        // Every lambda below follows the same five-step contract: (1) null-check
        // BOTH auth_secret_codec_ AND pg_pool_ — stop() resets them while
        // ServerImpl still lives (~4664-4667 above); (2) lease a connection with a
        // bounded timeout; (3) take the cluster-wide `secrets_kek_op` session
        // advisory lock (detail::try_lock_kek_op / KekOpLockGuard above) —
        // non-blocking, so a concurrent KEK op is a `Conflict`, never a wait; (4)
        // call the codec; (5) classify and SANITISE any failure — a
        // codec-internal std::expected error string (which can carry
        // PQerrorMessage text) is spdlog::error'd server-side and NEVER copied
        // into KekOpResult, which crosses to the HTTP boundary (kek_routes.hpp
        // rule B).
        kek_routes_ = std::make_unique<KekRoutes>();
        {
            // Built into the MEMBER, not a block-scoped local: the same three
            // operations back BOTH the REST routes registered here and the MCP
            // twins wired further down (mcp_server_ does not exist yet at this
            // point). One instance means the two surfaces can never drift in
            // failure classification or remediation wording.
            KekOps& kek_ops = kek_ops_;
            kek_ops.rotate = [this]() -> KekOpResult {
                KekOpResult result;
                if (!auth_secret_codec_ || !pg_pool_) {
                    result.failure = KekOpResult::Failure::Unavailable;
                    record_kek_op_outcome("rotate", detail::kek_op_outcome_label(result.failure));
                    return result;
                }
                auto lease = pg_pool_->try_acquire_for(detail::kKekOpAcquireTimeout);
                if (!lease) {
                    result.failure = KekOpResult::Failure::Unavailable;
                    record_kek_op_outcome("rotate", detail::kek_op_outcome_label(result.failure));
                    return result;
                }
                switch (detail::try_lock_kek_op(lease.get())) {
                case detail::KekOpLockAttempt::kError: {
                    // Defensive release (gov cpp-safety BLOCKING / UP-1): we
                    // could not read the try-lock result, so we do NOT know
                    // whether the server granted it. Unlocking a lock we never
                    // held is a harmless `false`; skipping the release when it
                    // WAS granted returns a lock-holding connection to the pool
                    // and wedges every future KEK operation cluster-wide.
                    detail::KekOpLockGuard release_if_held{lease.get()};
                    result.failure = KekOpResult::Failure::Unavailable;
                    record_kek_op_outcome("rotate", detail::kek_op_outcome_label(result.failure));
                    return result;
                }
                case detail::KekOpLockAttempt::kConflict:
                    result.failure = KekOpResult::Failure::Conflict;
                    record_kek_op_outcome("rotate", detail::kek_op_outcome_label(result.failure));
                    return result;
                case detail::KekOpLockAttempt::kAcquired:
                    break;
                }
                detail::KekOpLockGuard lock_guard{lease.get()}; // released before `lease`
                                                                 // returns to the pool
                                                                 // (reverse declaration
                                                                 // order).

                // #2530 B3 — the whole 5-step sequence below runs while
                // holding the cluster-wide `secrets_kek_op` advisory lock
                // acquired above, so two servers pointed at the same database
                // can never both pass these checks. Order is load-bearing;
                // see kek_rotate_control.hpp's `evaluate_rotate_preconditions`
                // doc comment for why, and its [pg]-free unit tests for the
                // ordering pinned in isolation from a live rotate.

                // #2530 G7-S9: the pre-#2530 process-local pre-check (5
                // minutes, in-memory, no DB round trip) was REMOVED here —
                // it ran before the durable checks below with a hardcoded
                // interval that could not be configured down, so an operator
                // who set `--kek-min-rotate-interval` below 5 minutes was
                // still refused for the full 5 minutes on THIS path, and
                // this path never populated `cooldown_retry_after_ms`,
                // silently falling back to the dishonest 300000 constant
                // that was fixed everywhere else in this same round (#2530
                // B2/G7-B2). It was never the authoritative control (that's
                // steps 1-3 below, backed by `secrets.kek_meta.created_at`)
                // and the two connection-pool reads it saved (`rotate_clock`,
                // `live_kek_version_count`) happen on a path that has
                // already taken a pooled connection and the cluster-wide
                // advisory lock, so the savings were marginal against the
                // correctness/honesty cost. If a cheap pre-DB short-circuit
                // is wanted again, it must clamp to
                // `min(short_circuit_window, cfg_.kek_min_rotate_interval_secs)`
                // and populate an honest `cooldown_retry_after_ms` on that
                // path — do not reintroduce a hardcoded window.

                // Step 1 + step 2: the durable rotation clock feeds BOTH the
                // clock-anomaly check and the durable rate limit, from one
                // single-statement read so both timestamps come from the
                // same database server clock (SecretCodec::rotate_clock doc
                // comment) — never the app host's.
                auto clock = auth_secret_codec_->rotate_clock(lease.get());
                if (!clock) {
                    spdlog::error("KEK rotate: rotate_clock failed: {}",
                                 clock.error().internal_message);
                    result.failure =
                        (clock.error().kind == pg::SecretCodec::LifecycleError::Kind::query_canceled)
                            ? KekOpResult::Failure::QueryCanceled
                            : KekOpResult::Failure::Internal;
                    record_kek_op_outcome("rotate", detail::kek_op_outcome_label(result.failure));
                    return result;
                }

                // Step 3's input (live version count) is read up front too —
                // evaluate_rotate_preconditions decides in the contract order
                // regardless of the order these two DB reads happen in; only
                // the DECISION order (clock anomaly, then cooldown, then
                // ceiling) is load-bearing, not the read order.
                auto live = auth_secret_codec_->live_kek_version_count(lease.get());
                if (!live) {
                    spdlog::error("KEK rotate: live_kek_version_count failed: {}",
                                 live.error().internal_message);
                    result.failure =
                        (live.error().kind == pg::SecretCodec::LifecycleError::Kind::query_canceled)
                            ? KekOpResult::Failure::QueryCanceled
                            : KekOpResult::Failure::Internal;
                    record_kek_op_outcome("rotate", detail::kek_op_outcome_label(result.failure));
                    return result;
                }
                result.live_versions = static_cast<std::uint32_t>(*live);

                const auto pre = detail::evaluate_rotate_preconditions(
                    *clock, std::chrono::seconds{cfg_.kek_min_rotate_interval_secs}, *live,
                    static_cast<std::uint32_t>(cfg_.kek_max_live_versions));
                if (pre.failure != KekOpResult::Failure::None) {
                    result.failure = pre.failure;
                    result.cooldown_retry_after_ms = pre.cooldown_retry_after_ms;
                    result.clock_skew_secs = pre.clock_skew_secs;
                    switch (pre.failure) {
                    case KekOpResult::Failure::ClockAnomaly:
                        // #2530 G7-B6: report the observed skew MAGNITUDE, not
                        // just the boolean fact of the anomaly — a few
                        // seconds of NTP jitter and a row dated a year out
                        // demand completely different operator responses,
                        // and until this fix the log line (and the 503 body,
                        // see kek_routes.cpp's write_failure) could not tell
                        // them apart.
                        spdlog::error(
                            "KEK rotate refused: newest kek_meta row is dated {}s in the future "
                            "relative to the database server's own clock — the durable rotation "
                            "rate limit cannot be computed safely; investigate the database "
                            "server's clock before retrying. A FORWARD skew like this is NOT "
                            "self-clearing — it persists until real time catches up to the "
                            "stored timestamp, and there is no configuration escape for this "
                            "refusal (see docs/user-manual/server-admin.md)",
                            pre.clock_skew_secs);
                        break;
                    case KekOpResult::Failure::Cooldown:
                        spdlog::warn(
                            "KEK rotate refused: durable rotation rate limit not yet elapsed "
                            "({}ms remaining of --kek-min-rotate-interval={}s)",
                            pre.cooldown_retry_after_ms, cfg_.kek_min_rotate_interval_secs);
                        break;
                    case KekOpResult::Failure::VersionCeiling:
                        spdlog::warn("KEK rotate refused: live KEK version count {} has reached "
                                     "the configured ceiling --kek-max-live-versions={}", *live,
                                     cfg_.kek_max_live_versions);
                        break;
                    default:
                        break;
                    }
                    record_kek_op_outcome("rotate", detail::kek_op_outcome_label(result.failure));
                    return result;
                }

                // Step 4 (process-local cooldown stamp) was removed with the
                // pre-check itself — #2530 G7-S9 above.

                // Step 5: mint. Half-committed detection (#2395 rule):
                // SecretCodec::rotate_kek (secret_codec.hpp) documents that
                // active_version_ is ALREADY advanced by the time it can
                // fail — the only failure path after that point is a
                // rewrap_all() error; every earlier failure (init not run,
                // version-space exhausted, KEK generation, fingerprint
                // INSERT, BEGIN/COMMIT) returns strictly BEFORE
                // active_version_ is touched. So comparing
                // active_kek_version() before vs. after the call is a
                // reliable, contract-matching signal — and it is safe from a
                // concurrent-mutation false-positive because we hold the
                // cluster-wide `secrets_kek_op` lock for the entire call, so
                // no OTHER KEK operation (on this server or any other
                // pointed at the same database) can be advancing
                // active_version_ underneath us in this window.
                const std::uint32_t before = auth_secret_codec_->active_kek_version();

                // Why the try/catch, stated accurately so nobody deletes it as
                // boilerplate (Hermes pass 1 raised it; pass 2 corrected my
                // reasoning). It is NOT the audit hook: emit_audit
                // (pg/secret_codec.cpp:281-288) swallows every exception, so
                // the hook cannot throw out of rotate_kek. What CAN throw past
                // the mint is anything in the trailing rewrap_all — allocation
                // for a large result set being the realistic case.
                //
                // Either way the hazard is the same and is why the catch has to
                // stay: active_version_ has ALREADY advanced by then
                // (secret_codec.cpp:827), so an exception that escaped this
                // lambda would surface as a generic 500 rather than the
                // half-committed instruction, and an operator (or automation)
                // following the obvious impulse would retry /rotate and mint a
                // spurious version on top of an already-advanced one. Catching
                // here means the before/after version check runs on EVERY
                // failure path, thrown or returned.
                std::optional<std::uint32_t> rotated_version;
                bool rotate_threw = false;
                auto mint_error_kind = pg::SecretCodec::LifecycleError::Kind::database;
                try {
                    auto rotated = auth_secret_codec_->rotate_kek(lease.get());
                    if (rotated) {
                        rotated_version = *rotated;
                    } else {
                        mint_error_kind = rotated.error().kind;
                        spdlog::error("KEK rotate failed: {}", rotated.error().internal_message);
                    }
                } catch (const std::exception& e) {
                    rotate_threw = true;
                    spdlog::error("KEK rotate threw: {}", e.what());
                } catch (...) {
                    rotate_threw = true;
                    spdlog::error("KEK rotate threw a non-std exception");
                }
                if (!rotated_version) {
                    // #2530 B4: half-commit classification WINS — evaluated
                    // FIRST, and it overrides a query_canceled `Kind` on the
                    // underlying error. See
                    // kek_rotate_control.hpp::classify_rotate_mint_failure
                    // for why (the short version: retrying /rotate on a
                    // half-committed rotation mints a spurious, unretirable
                    // extra version every time — the operator must be told
                    // to call /rewrap regardless of what caused the trailing
                    // rewrap_all() to fail).
                    const std::uint32_t after = auth_secret_codec_->active_kek_version();
                    const bool version_advanced = after > before;
                    result.failure =
                        detail::classify_rotate_mint_failure(version_advanced, mint_error_kind);
                    if (rotate_threw && version_advanced)
                        spdlog::critical("KEK rotate threw AFTER advancing the active version to "
                                         "v{} — the mint committed; resume with /rewrap, do NOT "
                                         "retry /rotate",
                                         after);
                    record_kek_op_outcome("rotate", detail::kek_op_outcome_label(result.failure));
                    return result;
                }
                result.new_version = *rotated_version;
                // rotate_kek() runs its own internal rewrap_all() as part of
                // minting (secret_codec.cpp ~824-838) but DISCARDS that call's
                // row count, returning only the new version. Rather than
                // report `rows_rewrapped: 0` — which would be a confidently
                // wrong number on a rotation that in fact re-wrapped every row
                // — the /rotate response omits the count entirely and reports
                // `rotation_complete` instead. That is the signal an operator
                // actually needs (the ADR-0010 §3 completion signal), and it is
                // one we can produce truthfully: reaching here means
                // rotate_kek's internal rewrap_all() returned success, so no
                // row is left on a superseded version. An operator who wants a
                // count can call /rewrap, which reports a real one (0 when
                // there is genuinely nothing left to do).
                result.rotation_complete = true;
                record_kek_op_outcome("rotate", detail::kek_op_outcome_label(result.failure));
                return result;
            };
            kek_ops.rewrap = [this]() -> KekOpResult {
                KekOpResult result;
                if (!auth_secret_codec_ || !pg_pool_) {
                    result.failure = KekOpResult::Failure::Unavailable;
                    record_kek_op_outcome("rewrap", detail::kek_op_outcome_label(result.failure));
                    return result;
                }
                auto lease = pg_pool_->try_acquire_for(detail::kKekOpAcquireTimeout);
                if (!lease) {
                    result.failure = KekOpResult::Failure::Unavailable;
                    record_kek_op_outcome("rewrap", detail::kek_op_outcome_label(result.failure));
                    return result;
                }
                switch (detail::try_lock_kek_op(lease.get())) {
                case detail::KekOpLockAttempt::kError: {
                    // Defensive release (gov cpp-safety BLOCKING / UP-1): we
                    // could not read the try-lock result, so we do NOT know
                    // whether the server granted it. Unlocking a lock we never
                    // held is a harmless `false`; skipping the release when it
                    // WAS granted returns a lock-holding connection to the pool
                    // and wedges every future KEK operation cluster-wide.
                    detail::KekOpLockGuard release_if_held{lease.get()};
                    result.failure = KekOpResult::Failure::Unavailable;
                    record_kek_op_outcome("rewrap", detail::kek_op_outcome_label(result.failure));
                    return result;
                }
                case detail::KekOpLockAttempt::kConflict:
                    result.failure = KekOpResult::Failure::Conflict;
                    record_kek_op_outcome("rewrap", detail::kek_op_outcome_label(result.failure));
                    return result;
                case detail::KekOpLockAttempt::kAcquired:
                    break;
                }
                detail::KekOpLockGuard lock_guard{lease.get()};

                // rewrap_all() never mints a version — it only re-wraps rows
                // already on a non-active version under the current active one
                // — so there is no half-committed state to distinguish here.
                // #2530 item 3 completion: a canceled/timed-out rewrap scan
                // (LifecycleError::Kind::query_canceled) is now classified
                // as QueryCanceled rather than a generic Internal, matching
                // rotate's classification and the fixed metrics/audit
                // outcome vocabulary (both already carry a "query_canceled"
                // token that would otherwise never fire for this op).
                auto rewrapped = auth_secret_codec_->rewrap_all(lease.get());
                if (!rewrapped) {
                    spdlog::error("KEK rewrap failed: {}", rewrapped.error().internal_message);
                    result.failure =
                        (rewrapped.error().kind == pg::SecretCodec::LifecycleError::Kind::query_canceled)
                            ? KekOpResult::Failure::QueryCanceled
                            : KekOpResult::Failure::Internal;
                    record_kek_op_outcome("rewrap", detail::kek_op_outcome_label(result.failure));
                    return result;
                }
                result.rows_rewrapped = *rewrapped;
                record_kek_op_outcome("rewrap", detail::kek_op_outcome_label(result.failure));
                return result;
            };
            kek_ops.status = [this]() -> KekOpResult {
                KekOpResult result;
                if (!auth_secret_codec_ || !pg_pool_) {
                    result.failure = KekOpResult::Failure::Unavailable;
                    record_kek_op_outcome("status", detail::kek_op_outcome_label(result.failure));
                    return result;
                }
                auto lease = pg_pool_->try_acquire_for(detail::kKekOpAcquireTimeout);
                if (!lease) {
                    result.failure = KekOpResult::Failure::Unavailable;
                    record_kek_op_outcome("status", detail::kek_op_outcome_label(result.failure));
                    return result;
                }
                // status deliberately does NOT take the operation lock.
                //
                // It did in the first cut, to avoid a "torn" read across an
                // in-flight rotation. That was wrong twice over (gov
                // unhappy-path UP-3, security LOW):
                //
                //  1. It made the ONLY diagnostic unavailable exactly while the
                //     thing it diagnoses is running — an operator polling during
                //     a long rewrap got 409, indistinguishable from a wedged
                //     lock, which is the opposite of what a status endpoint is
                //     for.
                //  2. It let any Security:Read caller contend an exclusive lock
                //     against a running rotation, and burn a pooled connection
                //     waiting for it.
                //
                // And the "torn" read is not actually a problem: mid-rewrap we
                // observe oldest_in_use < active_version and report
                // rotation_complete=false, which is TRUE and is precisely the
                // in-progress signal the operator wants. A momentarily stale
                // read errs toward "not complete", never toward a false
                // "complete".
                //
                // #2530 B2/B6: `live_versions`/`lock_held`/`lock_holder_pid`
                // are each their own SELECT, taken lock-free at possibly
                // different instants (KekOpResult doc comment) — this route
                // STILL never takes `secrets_kek_op` itself; the lock-holder
                // observation below only ever OBSERVES via pg_locks.
                result.active_version = auth_secret_codec_->active_kek_version();
                auto oldest = auth_secret_codec_->oldest_kek_version_in_use(lease.get());
                if (!oldest) {
                    spdlog::error("KEK status: oldest_kek_version_in_use failed: {}",
                                 oldest.error().internal_message);
                    result.failure =
                        (oldest.error().kind == pg::SecretCodec::LifecycleError::Kind::query_canceled)
                            ? KekOpResult::Failure::QueryCanceled
                            : KekOpResult::Failure::Internal;
                    record_kek_op_outcome("status", detail::kek_op_outcome_label(result.failure));
                    return result;
                }
                result.oldest_in_use = *oldest;
                // Completion is `== active_version`, NOT `>=` (gov unhappy-path
                // UP-6). A row whose header references a version HIGHER than the
                // active one is an anomaly — a restore against a newer keys dir,
                // or a blob from another install — and `>=` would report that
                // state as "complete", which is the worst possible false
                // comfort: it says "every secret is on the current key" about
                // rows whose key is not even registered here.
                if (!result.oldest_in_use.has_value()) {
                    result.rotation_complete = true; // no secret rows at all
                } else if (*result.oldest_in_use > result.active_version) {
                    spdlog::error("KEK status: oldest referenced version v{} EXCEEDS the active "
                                  "version v{} — a secret row references a KEK this install has "
                                  "not registered (restore skew?); reporting NOT complete",
                                  *result.oldest_in_use, result.active_version);
                    result.rotation_complete = false;
                } else {
                    result.rotation_complete = (*result.oldest_in_use == result.active_version);
                }

                // #2530 B2/B6/T5 diagnostic snapshots. Both queries here are
                // deliberately non-fatal to the whole status response — a
                // live_kek_version_count or lock-holder outage shouldn't
                // take down the rest of an otherwise-healthy status read —
                // but a query failure degrades its ONE field to `nullopt`
                // ("could not be determined"), NEVER to a fabricated
                // `0`/`false`. Yuzu's standing rule (already honoured by the
                // periodic metrics gauge sampled below, in
                // health_recompute_thread_) is that a value nobody could
                // determine is ABSENT, never a confident negative. This
                // matters most for `lock_held`: this field exists so an
                // operator can diagnose a backend wedged holding
                // `secrets_kek_op` — the failure mode where every KEK
                // operation 409s forever — and reporting `lock_held: false`
                // from a query FAILURE would tell them "there is no wedge"
                // during exactly the incident this field was added for.
                // Both failures are logged loudly here so they're
                // distinguishable in server logs from a truthful negative.
                //
                // Not bumping `yuzu_server_kek_metrics_unavailable_total`
                // here: that counter is specific to the scrape-time sampler
                // (health_recompute_thread_, #2530 B7) below, which samples
                // periodically regardless of request volume — overloading it
                // with this on-demand, per-request degrade would conflate
                // two different signals (cluster health cadence vs. one
                // caller's status read). `record_kek_op_outcome("status",
                // ...)` below still records this call as a successful status
                // read (the response is a 200 with an honest partial
                // degrade), which is the correct per-request outcome.
                auto live = auth_secret_codec_->live_kek_version_count(lease.get());
                if (live) {
                    result.live_versions = static_cast<std::uint32_t>(*live);
                } else {
                    spdlog::error("KEK status: live_kek_version_count failed: {}",
                                 live.error().internal_message);
                }
                auto holder = detail::kek_op_lock_holder(lease.get());
                if (holder.determined) {
                    // #2530 G7-S1: read `lock_held` directly rather than
                    // deriving it from `pid.has_value()` — a granted holder
                    // row with a NULL pid is still held (see
                    // KekOpLockHolder's doc comment).
                    result.lock_held = holder.lock_held;
                    result.lock_holder_pid = holder.pid;
                    // #2530 H1: surface WHEN this snapshot was taken, not
                    // just what it said — a stale pid corroborated against
                    // pg_stat_activity minutes later can already belong to
                    // an unrelated backend (pids are reused).
                    result.lock_holder_captured_at = holder.captured_at;
                } else {
                    spdlog::error("KEK status: lock-holder query failed; lock_held/"
                                 "lock_holder_pid left undetermined (never fabricated false)");
                }

                record_kek_op_outcome("status", detail::kek_op_outcome_label(result.failure));
                return result;
            };
            kek_routes_->register_routes(*web_server_, perm_fn, audit_fn, kek_ops);
        }

        // -- SCIM v2 provisioning (/scim/v2/*) — enterprise IdP auto-(de)provisioning --
        // Routes + the configured bearer token are entirely inert when
        // disabled: no route table entries at all. scim_store_ itself was
        // already constructed (born-on-PG, unconditional) in the ctor above
        // — main.cpp already refuses to start if --scim-enable is set without
        // --scim-token or without HTTPS (CC6.2 fail-closed).
        if (cfg_.scim_enable) {
            // sec-L3/UP-9 (governance hardening round): trim leading/trailing
            // ASCII whitespace from the admin-group config value — same
            // trailing-space silent-lockout bug fixed for
            // --oidc-admin-group/--saml-admin-group above. Mutate cfg_
            // itself so every reader of cfg_.scim_admin_group (the routes
            // registration below, recompute_scim_user_role) sees the
            // trimmed value.
            cfg_.scim_admin_group = trim_ascii_whitespace(cfg_.scim_admin_group);

            if (!scim_store_ || !scim_store_->is_open()) {
                // H3 (2026-07-08 review): previously logged-and-continued,
                // which left /scim/v2/* permanently rejecting every request
                // (require_bearer always fails against a closed store)
                // while /readyz's "scim_store" check (below) reported
                // green — an operator would have no signal that the
                // surface never came up. Set startup_failed_ instead; the
                // guard immediately below this block aborts start_web_server()
                // before the web listener launches, and run() (after its
                // start_web_server() call) stops the already-started
                // agent/management gRPC listeners and returns, so main.cpp
                // exits non-zero on startup_failed() — matching main.cpp's
                // own "refuses to start without a token" fail-closed posture
                // for this same feature.
                spdlog::error("SCIM: the SCIM resource/token store (scim_store schema) is not "
                             "open — refusing to start.");
                startup_failed_ = true;
            } else if (!scim_store_->set_token(cfg_.scim_token, "boot")) {
                // H3: same reasoning — a persist failure here is just as
                // fatal to the surface as a closed store (require_bearer
                // has no token to validate against), but is_open() alone
                // would still read true, so this branch needs its own
                // fail-closed guard rather than relying on the store-open
                // check above. See the comment on the is_open() branch above
                // for how startup_failed_ actually halts serving.
                spdlog::error("SCIM: failed to store the configured --scim-token — "
                             "refusing to start.");
                startup_failed_ = true;
            }
            scim_routes_ = std::make_unique<ScimRoutes>();
            scim_routes_->register_routes(*web_server_, scim_store_.get(), &auth_mgr_,
                                          audit_store_.get(), cfg_.scim_admin_group,
                                          engine_principal_store_.get());
        }

        // M/H3 follow-up (2026-07-10 review): a SCIM boot failure above set
        // startup_failed_, but nothing checked it here — start_web_server()
        // continued registering every other route and unconditionally
        // launched the web listener thread below, and run() went on to
        // agent_server_->Wait() with no re-check. The server ended up
        // SERVING (agent gRPC + web) despite "refusing to start". Abort now:
        // skip the rest of route registration and never launch the web
        // listener. run() re-checks startup_failed_ immediately after its
        // start_web_server() call and stops the already-started agent/
        // management gRPC listeners before reaching agent_server_->Wait().
        if (startup_failed_) {
            spdlog::critical(
                "start_web_server(): aborting — SCIM boot failure above set startup_failed_; "
                "the web listener will not be started.");
            return;
        }

        // -- A2 discovery surface (roadmap Issue 17.1): /api/v1/discover/* --------
        // Agentic-first (A1/A2, docs/agentic-first-principle.md) — RBAC permission
        // catalog, published instruction definitions, REST route catalog (subset of
        // the SAME OpenAPI document /api/v1/openapi.json serves), Scope DSL kinds +
        // operators, and the plugin/action catalog observed across the fleet. No
        // AuditFn: these are catalog/schema reads, not per-device PII — matches the
        // GET /guaranteed-state/schemas precedent this module is modeled on.
        discover_routes_ = std::make_unique<DiscoverRoutes>();
        discover_routes_->register_routes(*web_server_, auth_fn, perm_fn, rbac_store_.get(),
                                          instruction_store_.get(), &registry_);

        // DEX app-perf-over-time read providers (slice 2). One bundle of B1/B2
        // store seams shared by the REST endpoints and the MCP twins so both read
        // the SAME substrate. Each lambda null-checks the store at call time and
        // returns std::nullopt on an unwired/closed store (the read surfaces map a
        // nullopt to a 503 degrade, never a silent empty). The `app_perf_providers`
        // bundle is built once ABOVE (before the DexRoutes registration) so the
        // dashboard, REST and MCP surfaces all share the same store seams.

        // -- Register REST API v1 routes (Phase 3) --------------------------------

        // PR 4.3 (T13): shared owner-existence resolver for the
        // engine-principal create/transfer-owner FK check — RestApiV1 and
        // McpServer both need the identical "does this username name a real
        // user" predicate. AuthDB::user_exists is non-const and returns
        // std::expected<bool, AuthDBError> (no value_or on std::expected);
        // a lookup failure reads as "does not exist" — fail-closed on the
        // owner FK, same posture break_glass_account_problem uses elsewhere
        // in auth_db.cpp.
        auto engine_owner_exists_fn = [this](const std::string& username) -> bool {
            auto* db = auth_mgr_.auth_db_ptr();
            if (db == nullptr)
                return false;
            auto exists = db->user_exists(username);
            return exists.has_value() && *exists;
        };

        rest_api_v1_ = std::make_unique<RestApiV1>();
        // Both setters MUST run BEFORE register_routes() (captured by value
        // at registration time, not `this`) — see set_engine_principal_store/
        // set_user_exists_fn's doc comments in rest_api_v1.hpp. Nullable:
        // an unwired engine_principal_store_ leaves the engine-principal
        // routes answering 503, same posture as every other optional-store
        // wiring in this file.
        if (engine_principal_store_) {
            rest_api_v1_->set_engine_principal_store(engine_principal_store_.get());
            rest_api_v1_->set_user_exists_fn(engine_owner_exists_fn);
        }
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
                bool api_tokens_db_persisted = true; // vacuously true when not requested
                if (revoke_api_tokens && api_token_store_ && api_token_store_->is_open()) {
                    auto revoked = api_token_store_->revoke_for_principal(username);
                    if (revoked.has_value()) {
                        tokens = *revoked;
                    } else {
                        // The API-token revoke did NOT persist (lease timeout /
                        // query error). Do NOT report a count — 0 would read as
                        // "the principal had no tokens". Flag it so the handler
                        // audits "partial", never a false "signed out
                        // everywhere" (ADR-0030 §Posture, the stolen-laptop path).
                        api_tokens_db_persisted = false;
                        spdlog::error("revoke_for_principal did not persist for {}: {}", username,
                                      revoked.error());
                    }
                }
                // CC7.2 anomaly-detection signal: a spike in this counter
                // is the operator's automated alert for compromised-account
                // response or rogue automation calling /me in a loop.
                // Caller dimension is inferred from the api-tokens flag:
                // /me passes true (self full-credential revoke), admin
                // path passes false (cookies only, automation tokens
                // intact). Result dimension is "partial" if EITHER the cookie
                // dual-write OR the API-token revoke failed, so SOC 2
                // partial-failure rows are filterable.
                const bool all_persisted = revoke.db_persisted && api_tokens_db_persisted;
                metrics_
                    .counter("yuzu_auth_sessions_revoked_total",
                             {{"caller", revoke_api_tokens ? "self" : "admin"},
                              {"result", all_persisted ? "success" : "partial"},
                              {"scope", revoke_api_tokens ? "all" : "cookies"}})
                    .increment();
                return RestApiV1::SessionRevokeResult{
                    revoke.count,
                    tokens,
                    revoke.db_persisted,
                    api_tokens_db_persisted,
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
            // #1788: the CONFINED closure — the same one WorkflowRoutes and the
            // dashboard execute surfaces take, NOT the system `command_dispatch_fn`.
            //
            // This wiring was the bug. RestApiV1 was handed the 6-arg system
            // closure (exec_visible hardcoded nullopt = unfiltered, correct only
            // for background engines), and the async result-set producers
            // (from-tar-query / from-instruction-result / re-eval) dispatched
            // through it — so a service-scoped token, admitted by their bare
            // global Execution:Execute gate, reached every connected agent
            // instead of its own service. RestApiV1::CommandDispatchFn is now
            // the 7-arg confined signature, so the unconfined closure is no
            // longer type-compatible with this parameter at all: the wrong
            // choice stopped being available rather than merely being avoided.
            // Empty closure would 503 those routes.
            command_dispatch_confined_fn,
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
                    // No rs_store/principal passed. A scope referencing
                    // from_result_set: now ABORTS (nullopt, H1) instead of
                    // silently evaluating the atom false (which a NOT
                    // combinator inverted to a fleet-wide arm);
                    // value_or({}) collapses the abort to zero targets —
                    // arm nothing, the safe direction on the push path.
                    targets = registry_.evaluate_scope(*parsed, tag_store_.get(),
                                                       custom_properties_store_.get())
                                  .value_or(std::vector<std::string>{});
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
                            // Same H1 semantics as above: a from_result_set:
                            // atom aborts to nullopt; value_or({}) => this
                            // agent is treated as out-of-scope (arm nothing).
                            auto v = registry_.evaluate_scope(*parsed, tag_store_.get(),
                                                              custom_properties_store_.get())
                                        .value_or(std::vector<std::string>{});
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
            // lockout_clear_fn — admin unlock (POST /api/v1/users/<name>/unlock).
            // Wraps AuthDB::clear_failed_logins so RestApiV1 stays decoupled from
            // AuthDB (same injection pattern as session_revoke_fn). SOC 2 CC6.3.
            // Empty/null auth_db ⇒ false ⇒ the route 500s and audits the failure.
            [this](const std::string& username) -> bool {
                auto* db = auth_mgr_.auth_db_ptr();
                return db && db->clear_failed_logins(username).has_value();
            },
            // Baseline-anchored per-device Guardian status route (trailing optional deps).
            baseline_store_.get(),
            // Per-device-scoped permission (management-group aware): the SAME
            // require_scoped_permission closure the dashboard device routes + the
            // agentic-first /api/v1/dex/devices/* endpoints use, so a REST worker is
            // held to the same per-device scope (defined once above, not re-inlined).
            scoped_perm_fn,
            // ADR-0016: the typed daily-sync software store + its per-device
            // Inventory-scope predicate for GET /api/v1/inventory/software. SAME
            // management-group chokepoint (check_scoped_permission) as the MCP
            // query_installed_software tool, bound to ("Inventory","Read"), so a
            // REST worker's fleet-wide software query returns only devices inside
            // their groups (cross-operator isolation). MUST be wired here; the
            // param defaults to {} = no filter (unscoped fleet read).
            software_inventory_store_.get(),
            [this](const std::string& username, const std::string& agent_id) -> bool {
                if (!rbac_store_ || !rbac_store_->is_rbac_enabled())
                    return true;
                return rbac_store_->check_scoped_permission(username, "Inventory", "Read", agent_id,
                                                            mgmt_group_store_.get());
            },
            // #1634: per-agent Response-scope predicate for the fan-out response
            // readers (GET /api/v1/executions/{id}/visualization). Routes through the
            // single response_agent_in_scope helper so the REST, MCP and legacy
            // surfaces share ONE fail-closed implementation (UP-1: a corrupt rbac.db
            // can't re-open the IDOR via a drifted copy). MUST be wired here; the param
            // defaults to {} = no filter.
            [this](const std::string& username, const std::string& agent_id) -> bool {
                return response_agent_in_scope(username, agent_id);
            },
            // DEX app-perf-over-time read providers (slice 2) — fleet trend + picker.
            app_perf_providers,
            // PR 4.2 — fleet-wide engine role-assignment authoring surface.
            engine_principal_store_.get(),
            // Periodic Access Reviews (SOC 2 CC6.2) — the campaign store plus the
            // read-model deps build_access_review needs beyond the ones already
            // threaded above (rbac_store_, engine_principal_store_, api_token_store_).
            access_review_store_.get(), auth_mgr_.auth_db_ptr(), directory_sync_.get(),
            // ADR-0034: the ONE held-open-response budget. GET /api/v1/events pins an
            // httplib worker for the life of its subscription, so it leases like every
            // other streaming surface. This wiring was MISSING: the parameter defaults
            // to nullptr, so the route's try_acquire block was dead code on a real
            // server while the boot log ("EVERY streaming surface leases from one
            // budget"), stream_budget.hpp's own "a surface that held a worker without a
            // lease would make the arithmetic here a fiction", and the documented 429 in
            // rest-api.md all asserted the opposite — and the plain-REST reserve was not
            // in fact reserved.
            stream_budget_.get(),
            // gov-fix(Gate-3-architect-F1): the same derive_exec_visible() the
            // /api/command handler and every MCP dispatch surface use, so REST
            // bundle dispatch gets the identical defense-in-depth confinement
            // check as its MCP execute_bundle twin (the scoped_perm_fn gate at
            // the handler remains the primary authorization).
            [this](const auth::Session& sess) { return derive_exec_visible(sess); });

        // -- Register MCP server routes ----------------------------------------

        if (cfg_.mcp_disable) {
            // C8: Return a proper JSON-RPC error instead of a generic 404.
            // CH-7(c): the disabled stub must ANSWER GET/DELETE too (not a bare
            // 404), so Streamable HTTP probes get the same honest disabled error.
            auto mcp_disabled_stub = [](const httplib::Request&, httplib::Response& res) {
                res.set_header("Content-Type", "application/json");
                res.set_content(
                    mcp::error_response_null(mcp::kMcpDisabled, "MCP is disabled on this server"),
                    "application/json");
            };
            web_server_->Post("/mcp/v1/", mcp_disabled_stub);
            web_server_->Get("/mcp/v1/", mcp_disabled_stub);
            web_server_->Delete("/mcp/v1/", mcp_disabled_stub);
        } else {
            mcp_server_ = std::make_unique<mcp::McpServer>();
            // In-memory session registry for Streamable HTTP (2f). Bounded,
            // non-durable. Safe as a raw borrow in the /mcp/v1/ handlers because
            // stop() joins the web server's worker threads (~ServerImpl → stop()
            // → web_server_->stop()) before any member destructs — no handler
            // runs after the join, so member-destruction order is irrelevant.
            mcp_sessions_ = std::make_unique<mcp::McpSessionRegistry>(
                mcp::McpSessionRegistry::Config{}, mcp::McpSessionRegistry::ClockFn{}, &metrics_);
            // Progress bridge core (2f PR 3a). Constructed only when the
            // execution bus exists (no instruction DB ⇒ no bus ⇒ bridge stays
            // null and execute_instruction never reserves - today's behavior).
            // Borrows the bus + registry raw; safe because stop() shuts the
            // bridge down and resets it BEFORE the bus resets, and the member
            // is declared after mcp_sessions_ ([BRIDGE-AFTER-SESSIONS]) so the
            // no-stop() teardown order is bridge → registry → (much earlier
            // decl) bus. The audit sink is request-free (G1 - the bridge's
            // lifecycle events fire from sweeps/projector, not a handler);
            // principal "system" marks them as server-side maintenance rows.
            if (execution_event_bus_) {
                mcp_stream_bridge_ = std::make_unique<mcp::McpStreamBridge>(
                    execution_event_bus_.get(), mcp_sessions_.get(), &metrics_,
                    [this](const std::string& action, const std::string& execution_id,
                           const std::string& detail,
                           mcp::McpStreamBridge::AuditResult result,
                           const std::string& actor) {
                        if (audit_store_ && audit_store_->is_open()) {
                            AuditEvent ev;
                            ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count();
                            // EMPTY actor = the bridge's own background work (sweep/projector).
                            // A non-empty one is an authenticated client whose action
                            // produced this row - stamping those "system" would make a
                            // client-driven cancel indistinguishable from housekeeping
                            // and defeat Decision 15(j) non-repudiation.
                            ev.principal = actor.empty() ? std::string("system") : actor;
                            ev.action = action;
                            ev.target_type = "Execution";
                            ev.target_id = execution_id;
                            ev.detail = detail;
                            // NOT hardcoded "success" (#2487 review): a teardown that
                            // could not complete, or a disposition that published
                            // nothing, must not be evidenced as a successful action.
                            ev.result =
                                result == mcp::McpStreamBridge::AuditResult::kFailure ? "failure"
                                                                                      : "success";
                            (void)audit_store_->log(ev);
                        }
                    });
                mcp_server_->set_stream_bridge(mcp_stream_bridge_.get());
            }
            // PR 4.3 (T13): wire the engine-principal store + the SAME
            // engine-credential store (api_token_store_) + the shared
            // owner-existence predicate the 8 engine tools need. Setters
            // are safe before OR after register_routes (the handler
            // captures `this`, see mcp_server.hpp's doc comment) but set
            // here, before build_handler() runs, for consistency with the
            // REST/settings wiring above. Nullable — an unwired
            // engine_principal_store_ leaves every engine-principal tool
            // answering "unavailable" rather than 503/crashing.
            // KEK ops are wired UNCONDITIONALLY, exactly as the REST routes are
            // (server.cpp's kek_routes_->register_routes above). This must NOT
            // sit inside the engine-principal conditional below: doing so made
            // the MCP tools answer "unavailable" whenever engine_principal_store_
            // was null while the REST twins worked fine — two surfaces
            // disagreeing about whether the same capability exists (ADR-1005 A1).
            mcp_server_->set_kek_ops(kek_ops_); // same seam instance as the REST twins
            if (engine_principal_store_) {
                mcp_server_->set_engine_principal_store(engine_principal_store_.get());
                mcp_server_->set_engine_credential_store(api_token_store_.get());
                mcp_server_->set_owner_exists_fn(engine_owner_exists_fn);
            }
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
                       const std::string& execution_id,
                       const yuzu::server::authz::VisibleSet& exec_visible)
                    -> std::pair<std::string, int> {
                    // MCP normalises an omitted target to kBroadcastScope upstream
                    // (mcp_server.cpp), so broadcast_on_none=true states its
                    // deliberate broadcast-on-empty contract. Same seam as the
                    // shared closure and the dashboard — one confined arm logic.
                    auto r = dispatch_confined(plugin, action, agent_ids, scope_expr, parameters,
                                               execution_id, exec_visible,
                                               /*broadcast_on_none=*/true);
                    spdlog::info("MCP execute_instruction: {}:{} → {} agent(s)", plugin, action,
                                 r.second);
                    return r;
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
                // #1550 HIGH-1 / #1634: per-agent response-scope predicate for
                // query_responses{execution_id} AND aggregate_responses. Routes through
                // the single response_agent_in_scope helper — the SAME fail-closed
                // implementation the REST + legacy surfaces use — so an operator
                // collects only the agents inside their groups, not any execution's rows
                // by id, and a corrupt rbac.db fails closed identically on every surface
                // (#1634 UP-1: was raw is_rbac_enabled, fail-open on store corruption).
                // The MCP handler resolves the principal ONCE (it already authed) and
                // passes `username` in, so this does NOT re-resolve the session per agent.
                // CAVEAT (#1634): for a service-scoped token this checks the token
                // CREATOR's RBAC scope, not the service-tag confinement that
                // require_scoped_permission's service branch applies — a pre-existing
                // MCP confinement limitation this does not fully close.
                [this](const std::string& username, const std::string& agent_id) -> bool {
                    return response_agent_in_scope(username, agent_id);
                },
                // ADR-0016: the typed daily-sync software store + its per-device
                // Inventory-scope predicate for query_installed_software. SAME
                // management-group chokepoint as the response predicate above, but
                // bound to ("Inventory","Read") — so an operator's fleet-wide software
                // query returns only devices inside their groups (cross-operator
                // isolation). MUST be wired here; the param defaults to {} = no filter.
                software_inventory_store_.get(),
                [this](const std::string& username, const std::string& agent_id) -> bool {
                    if (!rbac_store_ || !rbac_store_->is_rbac_enabled())
                        return true;
                    return rbac_store_->check_scoped_permission(username, "Inventory", "Read",
                                                                agent_id, mgmt_group_store_.get());
                },
                // ADR-0011: metrics sink for the MCP-surface bundle orchestrator
                // (yuzu_bundle_*{surface="mcp"}). REST passes its own registry.
                &metrics_,
                // DEX app-perf-over-time read providers (slice 2) — same bundle the
                // REST endpoints use, so MCP and REST read the SAME B1/B2 substrate.
                app_perf_providers,
                // #289 / Issue 13.5: the quarantine store backs the
                // quarantine_device write tool (record + real isolate), and the
                // tag-push closure fires the agent tag-push after set_tag exactly
                // like the REST PUT /api/v1/tags path (D4). Same closure body as
                // the REST registration above.
                quarantine_store_.get(),
                [this](const std::string& agent_id, const std::string& key) {
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
                // A2 discovery (roadmap Issue 17.1): backs the discover_plugins tool
                // via the SAME AgentRegistry::help_json() the REST /discover/plugins
                // route reads (discover_routes_ above).
                &registry_,
                // H1 (PR #1796): per-device scope gate for the device-targeted MCP
                // write tools (set_tag / delete_tag / quarantine_device) — the SAME
                // require_scoped_permission chokepoint the dashboard device routes
                // and REST per-device endpoints use, so a management-group-confined
                // operator cannot tag or isolate devices outside their groups.
                [this](const httplib::Request& req, httplib::Response& res,
                       const std::string& type, const std::string& op,
                       const std::string& agent_id) -> bool {
                    return require_scoped_permission(req, res, type, op, agent_id);
                },
                // MCP Streamable HTTP transport (ADR-1005 Decision 15, 2f): the
                // session registry, the --mcp-no-streaming kill switch (by live
                // pointer into cfg_), and the Origin allowlist.
                mcp_sessions_.get(), &cfg_.mcp_streaming_disable, cfg_.mcp_allowed_origins,
                // ADR-0024: the SLE discovery store backs the query_software_licenses
                // MCP twin of GET /api/v1/sle/agents/{id} (machine-scope facts; the
                // per-user user_ref PII stays on the audited REST drill).
                software_licensing_store_.get(),
                // PR 4.2 — engine role-assignment MCP twins.
                engine_principal_store_.get(),
                // Periodic Access Reviews (SOC 2 CC6.2) — the campaign store plus the
                // read-model deps the export/open_access_review twins need beyond what's
                // already threaded above (rbac_store_, engine_principal_store_,
                // api_token_store_ via set_engine_credential_store).
                access_review_store_.get(), auth_mgr_.auth_db_ptr(), directory_sync_.get(),
                // PR 2 (GET SSE channel): the SHARED held-open-stream budget (one
                // instance across every SSE surface on this worker pool) and the
                // per-tick credential re-validation seam. Both are raw borrows of
                // ServerImpl members — same lifetime argument as mcp_sessions_ above
                // (stop() joins the workers before any member destructs).
                stream_budget_.get(),
                [this](const httplib::Request& req,
                       const std::string& principal) -> mcp::StreamRevalidate {
                    return auth_routes_->revalidate_stream(req, principal);
                },
                // The operator's --mcp-max-streams-per-principal. Passing it is what
                // makes the flag mean anything: the attach site previously read the
                // compile-time default, so raising or lowering the flag was a no-op
                // on a control that parses, validates, logs and is documented.
                cfg_.mcp_max_streams_per_principal,
                // Explicit-principal audit sink for mcp.stream.close. The generic sink
                // re-derives the actor by resolving the request's credential when the row
                // is written; a close row is written at teardown, so on a
                // credential_revoked close that resolution fails BY DEFINITION and the row
                // naming the revoked principal would name nobody. Routed to
                // audit_log_for_principal, which stamps values captured at attach time.
                [this](const httplib::Request& req, const std::string& action,
                       const std::string& result, const mcp::StreamAuditPrincipal& principal,
                       const std::string& target_type, const std::string& target_id,
                       const std::string& detail) -> bool {
                    return auth_routes_->audit_log_for_principal(req, action, result, principal.id,
                                                                 principal.role, target_type,
                                                                 target_id, detail, principal.cls);
                },
                // #1788: per-request Execution:Execute visible-set deriver, so the MCP
                // execute_instruction / execute_bundle dispatch confines to the caller's
                // visible device set — the SAME derivation /api/command uses.
                [this](const auth::Session& s) -> yuzu::server::authz::VisibleSet {
                    return derive_exec_visible(s);
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
            // No on_behalf_guard here (ADR-1005): this instance routes nothing —
            // every request gets a 301 and the re-request hits the guarded main
            // listener, so this is not a bypass of the pre-routing chokepoint.
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

    /// The legacy `/api/chargen/*` + `/api/procfetch/fetch` sink.
    ///
    /// #1788: these are OPERATOR dispatch surfaces and are confined like every
    /// other one. They were missed by the original sweep because they do not
    /// route through `command_dispatch_fn` — they call the registry directly —
    /// and their bare global `require_permission("Execution","Execute")` gate
    /// admits a SERVICE-SCOPED token on its `ITServiceOwner` role grant with no
    /// target check, so before this they reached the entire fleet: verbatim the
    /// escape #1788 exists to close, on three routes the changelog claimed were
    /// already covered.
    ///
    /// An omitted target means the fleet (#2500), so this is the Broadcast arm —
    /// narrowed to the caller's visible set, exactly as a named `__all__` is.
    void forward_legacy_command(const httplib::Request& req, const std::string& plugin,
                                const std::string& action, httplib::Response& res) {
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
        // Resolve the session ONCE — require_auth writes an error response on
        // failure, so calling it twice could emit two. Fail CLOSED to a
        // present-empty set (reaches nobody), never nullopt (unfiltered);
        // the permission gate above has already admitted the caller, so this
        // only bites if the session vanished between the two.
        auto sess = require_auth(req, res);
        const yuzu::server::authz::VisibleSet exec_visible =
            sess ? derive_exec_visible(*sess)
                 : yuzu::server::authz::deny_all();
        const yuzu::server::ConfinedDispatchSink sink{
            [&](const std::string& aid) { return registry_.send_to(aid, cmd); },
            [&] { return registry_.send_to_all(cmd); },
            [&] { return registry_.all_ids(); }};
        int sent = yuzu::server::dispatch_confined_arms(
            yuzu::server::DispatchArm::Broadcast, {}, exec_visible,
            /*broadcast_on_none=*/false, sink);

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

    // ── json-taking overloads (#2500) ─────────────────────────────────────
    // The string-taking helpers above each parse the whole body. /api/command
    // called them eight times and this fix added a ninth parse of the same
    // string, on a route with no size cap beyond httplib's 100 MB default.
    // These let a handler that has ALREADY parsed reuse the object. Semantics
    // are deliberately identical to their string twins — same key checks, same
    // type checks, same fallbacks — so reusing the parse cannot change what a
    // field resolves to. Consolidating the remaining pre-auth parses needs the
    // plugin/action check moved relative to require_permission and is tracked
    // separately.
    static std::string extract_json_string(const nlohmann::json& j, const std::string& key) {
        if (j.is_object() && j.contains(key) && j[key].is_string())
            return j[key].get<std::string>();
        return {};
    }

    static std::unordered_map<std::string, std::string>
    extract_json_string_map(const nlohmann::json& j, const std::string& key) {
        std::unordered_map<std::string, std::string> result;
        if (j.is_object() && j.contains(key) && j[key].is_object()) {
            for (auto& [k, v] : j[key].items())
                result[k] = v.is_string() ? v.get<std::string>() : v.dump();
        }
        return result;
    }

    static int32_t extract_json_int(const nlohmann::json& j, const std::string& key,
                                    int32_t default_value = 0) {
        if (j.is_object() && j.contains(key) && j[key].is_number_integer())
            return j[key].get<int32_t>();
        return default_value;
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

    // SAML 2.0 SP — constructed once at startup (xmlsec global init is not
    // thread-safe); never mutated after construction, so no mutex is needed.
    // Null when SAML is not configured or on Windows (fail-closed).
    std::unique_ptr<saml::SamlProvider> saml_provider_;

    // NVD CVE feed
    std::shared_ptr<NvdDatabase> nvd_db_;
    std::unique_ptr<NvdSyncManager> nvd_sync_;
    // Serializes the /metrics emit of yuzu_nvd_sync_failures_total so two concurrent scrapes
    // can't double-apply the same per-reason delta (#1912 review).
    mutable std::mutex nvd_metrics_scrape_mu_;

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
    /// Born-on-PG persistence for /auto pre-flight runs. Borrows pg_pool_ →
    /// declared after it so it destructs before the pool; reset in stop().
    std::unique_ptr<PreflightRunStore> preflight_run_store_;
    std::unique_ptr<DeploymentRunStore> deployment_run_store_;
    /// Born-on-PG CAVM findings + per-agent coverage projection (ADR-0012).
    /// Borrows pg_pool_ → declared after it; reset in stop() before the pool.
    /// DORMANT this PR: constructed + wired into /readyz+/healthz, no engine yet.
    std::unique_ptr<VulnFindingStore> vuln_finding_store_;
    /// Born-on-PG campaign persistence for Periodic Access Reviews (SOC 2 CC6.2).
    /// Borrows pg_pool_ → declared after it; reset in stop() before the pool.
    std::unique_ptr<AccessReviewStore> access_review_store_;
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
    // F5 (Hermes pass-2 MEDIUM M3): engine_principal_store_ MUST be declared
    // BEFORE api_token_store_ — order is load-bearing, same pattern as the
    // rbac_store_/mgmt_group_store_ note above. api_token_store_'s
    // `set_engine_referent_check` resolver captures `this` and derefs
    // `engine_principal_store_` on every `create_token` call. Members
    // destruct in REVERSE declaration order, so declaring
    // engine_principal_store_ first means it destructs SECOND (after
    // api_token_store_) — it always outlives the resolver holder. The
    // opposite order would let engine_principal_store_ be destroyed while
    // api_token_store_ (and its resolver) still exists, so a late
    // `create_token` call during shutdown could deref a freed store. Do not
    // reorder these two. Both still borrow pg_pool_ and are declared after
    // it, so normal reverse-declaration-order destruction is correct there
    // too; stop() also explicitly resets api_token_store_ before
    // engine_principal_store_ before pg_pool_.reset() (ADR-0012
    // destruct-before-pool discipline).
    std::unique_ptr<EnginePrincipalStore> engine_principal_store_;
    std::unique_ptr<ApiTokenStore> api_token_store_;
    std::unique_ptr<QuarantineStore> quarantine_store_;
    /// Migrated Postgres store (ADR-0006/ADR-0036, schema `result_set_store`).
    /// Borrows pg_pool_ (declared earlier, destructs later) — declared here so
    /// it destructs after the ingest/HTTP paths that hold its raw pointer and
    /// before the pool; explicit reset() in stop() before pg_pool_.reset().
    std::unique_ptr<ResultSetStore> result_set_store_;
    std::unique_ptr<PolicyStore> policy_store_;
    std::unique_ptr<PolicyEvaluator> policy_evaluator_;
    std::unique_ptr<PreflightRunner> preflight_runner_; // borrows run+response stores
    std::unique_ptr<ScheduleRunner> schedule_runner_;   // borrows engine + stores (#1191)
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
    // Shared admission budget for held-open SSE responses (2f PR 2, Decision 15(h)).
    // ONE instance for the whole web server — the streamed-POST channel (2f PR 3) and
    // /api/v1/events (#2056) take leases from THIS object rather than minting their own
    // counters, or the shared worker pool can still be starved by whichever surface
    // opted out.
    //
    // DECLARED BEFORE mcp_sessions_ ON PURPOSE: every Lease borrows this budget, and a
    // Lease is reachable both from a session's stream state and from a provider closure
    // living on a worker stack. Members destruct in reverse declaration order, so the
    // budget must be declared FIRST to outlive its borrowers. NOTE the borrowers on
    // worker stacks are only reaped when web_server_'s pool is joined — that join is
    // load-bearing and this ordering is defence in depth behind it, not a replacement
    // for it (web_server_ is declared earlier still, so it destructs after this).
    std::unique_ptr<detail::StreamBudget> stream_budget_;
    // MCP Streamable HTTP session registry (2f). Captured by raw pointer into the
    // /mcp/v1/ handlers; safe because stop() joins web_server_ before members
    // destruct (see ~ServerImpl → stop() → web_server_->stop()).
    std::unique_ptr<mcp::McpSessionRegistry> mcp_sessions_;
    // [BRIDGE-AFTER-SESSIONS] - DO NOT reorder these two members or insert a new
    // member between them. The progress bridge (2f PR 3a) borrows BOTH the
    // registry (stream_for/exists) and the execution bus (subscribe/unsubscribe)
    // by raw pointer; members destruct in reverse declaration order, so the
    // bridge declared AFTER mcp_sessions_ destructs FIRST (its dtor runs the
    // idempotent shutdown(): joins the projector and unsubscribes from the bus
    // while both borrows are still alive - the bus is declared far earlier and
    // destructs later still). The explicit stop() path mirrors this: bridge
    // shutdown+reset BEFORE execution_tracker_/bus reset. Same contract family
    // as [BUS-BEFORE-TRACKER]; grep both tags before touching this block.
    std::unique_ptr<mcp::McpStreamBridge> mcp_stream_bridge_;
    std::unique_ptr<ComplianceRoutes> compliance_routes_;
    std::unique_ptr<GuardianRoutes> guardian_routes_;
    std::unique_ptr<DexRoutes> dex_routes_;
    std::unique_ptr<NetworkRoutes> network_routes_;
    std::unique_ptr<DeviceRoutes> device_routes_;
    std::unique_ptr<InventoryRoutes> inventory_routes_;
    std::unique_ptr<SleRoutes> sle_routes_;
    std::unique_ptr<PreflightRoutes> preflight_routes_;
    std::unique_ptr<VerifyRoutes> verify_routes_;
    std::unique_ptr<DeploymentRoutes> deployment_routes_;
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
    std::unique_ptr<KekRoutes> kek_routes_; // #2395: /api/v1/secrets/kek/*
    // The three KEK operations, shared by the REST routes above and the MCP
    // twins. Each lambda captures `this` and re-checks auth_secret_codec_ and
    // pg_pool_ at CALL time, because stop() resets both while this object is
    // still alive. Held as a member (not a local) purely so both surfaces get
    // the same instance — see the registration site.
    KekOps kek_ops_;
    // #2530 G7-S9: the process-local rotate cooldown (mutex + timestamp) that
    // used to live here was REMOVED — it was superseded by the durable,
    // cluster-wide rate limit read from `secrets.kek_meta.created_at`
    // (`--kek-min-rotate-interval`, evaluated in the `kek_ops.rotate` seam
    // below) and had degraded into a correctness bug: its hardcoded 5-minute
    // window could not be configured down and never populated an honest
    // `cooldown_retry_after_ms`. See the removal comment at the former
    // check site in the `kek_ops.rotate` seam for the full rationale.

    // #2530 B7 — `yuzu_server_kek_operations_total{op,outcome}`. Follows the
    // `yuzu_server_secret_decrypt_failures_total` pull-model precedent
    // (~L4263): incremented HERE, at each kek_ops.{rotate,rewrap,status}
    // return point (in-process, no DB access — this is NOT a Postgres query),
    // and published as a `set()` of the current cumulative total by
    // health_recompute_thread_ every ~15s, so the scrape reads a monotonic
    // counter it never has to compute itself.
    std::mutex kek_op_outcome_mu_;
    std::map<std::pair<std::string, std::string>, std::uint64_t> kek_op_outcome_counts_;

    /// Thread-safe increment of one (op, outcome) cell. `outcome` MUST be one
    /// of the fixed #2530 B7 vocabulary tokens (`detail::kek_op_outcome_label`,
    /// kek_rotate_control.hpp) — never a free-form string, or the metric
    /// grows an unbounded label cardinality.
    void record_kek_op_outcome(std::string_view op, std::string_view outcome) {
        std::lock_guard<std::mutex> lk{kek_op_outcome_mu_};
        ++kek_op_outcome_counts_[{std::string(op), std::string(outcome)}];
    }

    // ── Postgres-backed AuthDB (ADR-0006 substrate migration) + its
    // dependency chain ──────────────────────────────────────────────────
    // Declared in this EXACT order — FileKeyProvider → SecretCodec → AuthDB
    // → ScimStore — so reverse-declaration-order destruction is safe:
    // AuthDB's background provisional-MFA reaper thread (started in its
    // ctor) touches both secret_codec_ and pg_pool_, so it MUST stop before
    // either goes away; declaring auth_db_ after auth_secret_codec_ (which
    // is after auth_key_provider_) guarantees the reaper joins (~AuthDB)
    // before the codec/provider destruct. Both auth_db_ and scim_store_
    // borrow pg_pool_ (declared far above, near metrics_) by reference, so
    // they must destruct before it — true here since every member below
    // this point is declared, hence destructs, before pg_pool_ does.
    std::unique_ptr<FileKeyProvider> auth_key_provider_;
    std::unique_ptr<pg::SecretCodec> auth_secret_codec_;
    std::unique_ptr<AuthDB> auth_db_;
    // SCIM v2 provisioning (/scim/v2/*) — the store is constructed
    // unconditionally alongside AuthDB (born-on-PG, cheap to open); only
    // route registration + the configured bearer token are gated on
    // --scim-enable (start_web_server()). ScimStore holds its own
    // independent PgPool lease per call (see scim_store.hpp — no shared-
    // connection lock order with AuthDB); scim_routes_ borrows non-owning
    // ScimStore*/AuthManager*/AuditStore* pointers, all of which outlive it.
    std::unique_ptr<ScimStore> scim_store_;
    std::unique_ptr<ScimRoutes> scim_routes_;
    std::unique_ptr<DiscoverRoutes> discover_routes_; // A2: /api/v1/discover/* (Issue 17.1)

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
    // Typed software-inventory projection — born-on-Postgres (ADR-0016).
    // Declared after pg_pool_ so it destructs before the pool.
    std::unique_ptr<SoftwareInventoryStore> software_inventory_store_;
    std::unique_ptr<SoftwareCatalogRollup> software_catalog_rollup_;
    // Typed per-device app-perf daily projection — born-on-Postgres (DEX
    // app-perf-over-time B1). Declared after pg_pool_ so it destructs before the pool.
    std::unique_ptr<AppPerfDailyStore> app_perf_daily_store_;
    std::unique_ptr<DeviceInventoryStore> device_inventory_store_;
    // SLE detected-licence store (ADR-0024 Decision 4). Declared after pg_pool_
    // so it destructs before the pool.
    std::unique_ptr<SoftwareLicensingStore> software_licensing_store_;
    // SLE canonical product registry (ADR-0024 Decision 4). Declared after pg_pool_
    // so it destructs before the pool; the /api/v1/sle/* routes read it (the UCE
    // module's evaluator writes it, out-of-server).
    std::unique_ptr<ProductRegistryStore> product_registry_store_;
    // Fleet-aggregate app-perf (B2) + its cross-store roll-up query owner (ADR-0012).
    // Declared after pg_pool_ so they destruct before the pool.
    std::unique_ptr<AppPerfFleetStore> app_perf_fleet_store_;
    std::unique_ptr<AppPerfRollup> app_perf_rollup_;
    // Slice-2 group-trend reader (reads B1 by member list; borrows the pool).
    std::unique_ptr<AppPerfGroupReader> app_perf_group_reader_;
    std::unique_ptr<AppPerfCohortReader> app_perf_cohort_reader_; // /auto VERIFY compare

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
    std::thread app_perf_rollup_thread_;
    std::thread preflight_runner_thread_; // joined before stores in stop()
    std::thread schedule_tick_thread_;    // drives ScheduleRunner (#1191); joined before stores
    std::thread result_set_maint_thread_;

    // Periodic reminder when running with --insecure-skip-client-verify (issue #79)
    std::thread insecure_tls_reminder_thread_;

    // T12 (design doc §7): engine-credential overlap-pair rotation sweep —
    // auto-revoke elapsed predecessors + the successor-unused warning. A
    // dedicated thread rather than piggybacking on health_recompute_thread_:
    // that thread's own comment (see start_web_server()) already flags its
    // sweep body as a serial budget shared with a SECURITY-relevant
    // revocation sweep — adding unrelated PG-bound work there would grow
    // that shared stall window. Joined before api_token_store_ resets in
    // stop() (it borrows api_token_store_ + audit_store_, same ADR-0012
    // destruct-before-pool discipline as every other PG-borrowing thread
    // here).
    std::thread engine_rotation_sweep_thread_;

    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> stop_entered_{false};
    std::atomic<bool> draining_{false};

    // Rate limiting
    RateLimiter api_rate_limiter_;
    RateLimiter login_rate_limiter_;

    // Per-principal quota cap (PR 4.4) — gates principal_kind=="engine"
    // sessions only, at the pre-routing chokepoint. See principal_quota.hpp.
    PrincipalQuota principal_quota_;
};

// -- Factory ------------------------------------------------------------------

std::unique_ptr<Server> Server::create(Config config, auth::AuthManager& auth_mgr) {
    return std::make_unique<ServerImpl>(std::move(config), auth_mgr);
}

} // namespace yuzu::server
