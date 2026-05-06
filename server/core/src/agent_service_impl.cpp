#include "agent_service_impl.hpp"

#include <grpc/grpc_security_constants.h>

#include "analytics_event_store.hpp"
#include "execution_tracker.hpp"
#include "inventory_store.hpp"
#include "management_group_store.hpp"
#include "notification_store.hpp"
#include "offload_target_store.hpp"
#include "response_store.hpp"
#include "result_parsing.hpp"
#include "tag_store.hpp"
#include "update_registry.hpp"
#include "web_utils.hpp"
#include "webhook_store.hpp"

// compare_versions is declared in nvd_db.hpp
#include "nvd_db.hpp"

namespace yuzu::server::detail {

// Bring html_escape into scope for the HTML rendering methods.
using yuzu::server::html_escape;

// -- Constructor --------------------------------------------------------------

AgentServiceImpl::AgentServiceImpl(AgentRegistry& registry, EventBus& bus,
                                   bool require_client_identity, auth::AuthManager& auth_mgr,
                                   auth::AutoApproveEngine& auto_approve,
                                   yuzu::MetricsRegistry& metrics, bool gateway_mode,
                                   UpdateRegistry* update_registry)
    : registry_(registry), bus_(bus), auth_mgr_(auth_mgr), auto_approve_(auto_approve),
      metrics_(metrics), require_client_identity_(require_client_identity),
      gateway_mode_(gateway_mode), update_registry_(update_registry) {}

// -- Register -----------------------------------------------------------------

grpc::Status AgentServiceImpl::Register(grpc::ServerContext* context,
                                        const pb::RegisterRequest* request,
                                        pb::RegisterResponse* response) {
    metrics_.counter("yuzu_grpc_requests_total", {{"method", "Register"}, {"status", "received"}})
        .increment();
    const auto& info = request->info();

    if (require_client_identity_) {
        if (!context || !peer_identity_matches_agent_id(*context, info.agent_id())) {
            spdlog::warn("mTLS identity mismatch: claimed agent_id={}", info.agent_id());
            return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                                "agent_id must match client certificate identity (CN/SAN)");
        }
    }

    // -- Tiered enrollment -------------------------------------------------------

    bool is_reauth = false; // Track whether this is a reconnection vs first enrollment

    // Fast path: agent already enrolled from a prior connection — skip enrollment
    {
        auto prior = auth_mgr_.get_pending_status(info.agent_id());
        if (prior && *prior == auth::PendingStatus::approved) {
            spdlog::info("Agent {} re-registering (already enrolled)", info.agent_id());
            is_reauth = true;
            goto enrolled;
        }
    }

    {
        const auto& enrollment_token = request->enrollment_token();

        if (!enrollment_token.empty()) {
            // Tier 2: Validate the pre-shared token
            if (!auth_mgr_.validate_enrollment_token(enrollment_token)) {
                spdlog::warn("Agent {} presented invalid enrollment token", info.agent_id());
                response->set_accepted(false);
                response->set_reject_reason("invalid, expired, or exhausted enrollment token");
                response->set_enrollment_status("denied");
                if (analytics_store_) {
                    AnalyticsEvent ae;
                    ae.event_type = "agent.enrollment_denied";
                    ae.agent_id = info.agent_id();
                    ae.hostname = info.hostname();
                    ae.os = info.platform().os();
                    ae.arch = info.platform().arch();
                    ae.severity = Severity::kWarn;
                    ae.attributes = {{"reason", "invalid_token"}};
                    analytics_store_->emit(std::move(ae));
                }
                return grpc::Status::OK;
            }
            spdlog::info("Agent {} auto-enrolled via enrollment token", info.agent_id());
            // Persist enrollment so reconnections don't need a valid token.
            // Returns false if the agent was explicitly denied by an admin.
            if (!auth_mgr_.ensure_enrolled(info.agent_id(), info.hostname(), info.platform().os(),
                                           info.platform().arch(), info.agent_version())) {
                response->set_accepted(false);
                response->set_reject_reason("enrollment denied by administrator");
                response->set_enrollment_status("denied");
                return grpc::Status::OK;
            }
        } else {
            // Tier 1.5: Auto-approve policies -- check before pending queue
            auth::ApprovalContext approval_ctx;
            approval_ctx.hostname = info.hostname();
            approval_ctx.attestation_provider = request->attestation_provider();

            // Extract peer IP from gRPC context (format: "ipv4:1.2.3.4:port")
            if (context) {
                auto peer = context->peer();
                // Strip scheme prefix and port
                auto colon1 = peer.find(':');
                if (colon1 != std::string::npos) {
                    auto ip_start = colon1 + 1;
                    auto colon2 = peer.rfind(':');
                    if (colon2 > ip_start) {
                        approval_ctx.peer_ip = peer.substr(ip_start, colon2 - ip_start);
                    } else {
                        approval_ctx.peer_ip = peer.substr(ip_start);
                    }
                }
            }

            auto matched_rule = auto_approve_.evaluate(approval_ctx);
            if (!matched_rule.empty()) {
                spdlog::info("Agent {} auto-approved by policy: {}", info.agent_id(), matched_rule);
                // Persist enrollment so reconnections skip enrollment entirely.
                // Returns false if admin-denied — admin denials outrank auto-approve.
                if (!auth_mgr_.ensure_enrolled(info.agent_id(), info.hostname(),
                                               info.platform().os(), info.platform().arch(),
                                               info.agent_version())) {
                    response->set_accepted(false);
                    response->set_reject_reason("enrollment denied by administrator");
                    response->set_enrollment_status("denied");
                    return grpc::Status::OK;
                }
                // Fall through to normal registration
            } else {
                // Tier 1: No token, no policy match -- check the pending queue
                auto pending_status = auth_mgr_.get_pending_status(info.agent_id());

                if (!pending_status) {
                    // First time seeing this agent -- add to pending queue
                    auth_mgr_.add_pending_agent(info.agent_id(), info.hostname(),
                                                info.platform().os(), info.platform().arch(),
                                                info.agent_version());

                    response->set_accepted(false);
                    response->set_reject_reason("awaiting admin approval");
                    response->set_enrollment_status("pending");
                    bus_.publish("pending-agent", info.agent_id());
                    spdlog::info("Agent {} placed in pending approval queue", info.agent_id());
                    if (analytics_store_) {
                        AnalyticsEvent ae;
                        ae.event_type = "agent.enrollment_pending";
                        ae.agent_id = info.agent_id();
                        ae.hostname = info.hostname();
                        ae.os = info.platform().os();
                        ae.arch = info.platform().arch();
                        analytics_store_->emit(std::move(ae));
                    }
                    return grpc::Status::OK;
                }

                switch (*pending_status) {
                case auth::PendingStatus::pending:
                    response->set_accepted(false);
                    response->set_reject_reason("still awaiting admin approval");
                    response->set_enrollment_status("pending");
                    return grpc::Status::OK;

                case auth::PendingStatus::denied:
                    response->set_accepted(false);
                    response->set_reject_reason("enrollment denied by administrator");
                    response->set_enrollment_status("denied");
                    if (analytics_store_) {
                        AnalyticsEvent ae;
                        ae.event_type = "agent.enrollment_denied";
                        ae.agent_id = info.agent_id();
                        ae.hostname = info.hostname();
                        ae.os = info.platform().os();
                        ae.arch = info.platform().arch();
                        ae.severity = Severity::kWarn;
                        ae.attributes = {{"reason", "admin_denied"}};
                        analytics_store_->emit(std::move(ae));
                    }
                    return grpc::Status::OK;

                case auth::PendingStatus::approved:
                    spdlog::info("Agent {} enrolled (admin-approved)", info.agent_id());
                    // Fall through to normal registration
                    break;
                }
            } // auto-approve else
        }
    } // end enrollment checks

enrolled:
    // -- Agent is enrolled -- proceed with registration --------------------------

    registry_.register_agent(info);
    // Auto-add to root management group
    if (mgmt_group_store_ && mgmt_group_store_->is_open())
        mgmt_group_store_->add_member(ManagementGroupStore::kRootGroupId, info.agent_id());

    if (analytics_store_) {
        AnalyticsEvent ae;
        ae.event_type = "agent.registered";
        ae.agent_id = info.agent_id();
        ae.hostname = info.hostname();
        ae.os = info.platform().os();
        ae.arch = info.platform().arch();
        ae.agent_version = info.agent_version();
        ae.attributes = {
            {"enrollment_method", request->enrollment_token().empty() ? "approval" : "token"},
            {"enrollment_type", is_reauth ? "reauth" : "initial"}};
        nlohmann::json plugins_list = nlohmann::json::array();
        for (const auto& p : info.plugins()) {
            plugins_list.push_back(p.name());
        }
        ae.payload = {{"plugins", plugins_list}};
        analytics_store_->emit(std::move(ae));
    }

    // Create notification for agent enrollment
    if (notification_store_ && notification_store_->is_open()) {
        notification_store_->create("success", "Agent Enrolled",
                                    "Agent " + info.agent_id() + " (" + info.hostname() +
                                        ") enrolled successfully");
    }

    // Fire webhook + offload for agent enrollment.
    //
    // Both sinks receive the same serialised body; we build the JSON +
    // dump it ONCE (perf-S1) outside either guard so that one sink being
    // disabled does not silently disable the other (HP-1 / UP-6
    // regression caught at Gate 4).
    if ((webhook_store_ && webhook_store_->is_open()) ||
        (offload_target_store_ && offload_target_store_->is_open())) {
        nlohmann::json payload = {
            {"event", "agent.registered"},    {"agent_id", info.agent_id()},
            {"hostname", info.hostname()},    {"os", info.platform().os()},
            {"arch", info.platform().arch()}, {"agent_version", info.agent_version()}};
        const auto body = payload.dump();
        if (webhook_store_ && webhook_store_->is_open()) {
            webhook_store_->fire_event("agent.registered", body);
        }
        if (offload_target_store_ && offload_target_store_->is_open()) {
            offload_target_store_->fire_event("agent.registered", body);
        }
    }

    // Sync agent-reported tags to persistent TagStore
    if (tag_store_ && !info.scopable_tags().empty()) {
        std::unordered_map<std::string, std::string> tags;
        for (const auto& [k, v] : info.scopable_tags()) {
            tags[k] = v;
        }
        tag_store_->sync_agent_tags(info.agent_id(), tags);
    }

    auto session_id =
        "session-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(16));
    response->set_session_id(session_id);
    response->set_accepted(true);
    response->set_enrollment_status("enrolled");

    PendingRegistration pending;
    pending.agent_id = info.agent_id();
    pending.register_peer = context ? context->peer() : std::string{};
    pending.peer_identities =
        context ? extract_peer_identities(*context) : std::vector<std::string>{};
    pending.created_at = std::chrono::steady_clock::now();
    {
        std::lock_guard lock(pending_mu_);
        prune_expired_pending_locked();
        pending_by_session_id_[session_id] = std::move(pending);
    }

    return grpc::Status::OK;
}

// -- Heartbeat ----------------------------------------------------------------

grpc::Status AgentServiceImpl::Heartbeat(grpc::ServerContext* /*context*/,
                                         const pb::HeartbeatRequest* request,
                                         pb::HeartbeatResponse* response) {
    metrics_.counter("yuzu_grpc_requests_total", {{"method", "Heartbeat"}, {"status", "received"}})
        .increment();

    // Validate session
    const auto& session_id = request->session_id();
    std::string agent_id;
    {
        std::lock_guard lock(pending_mu_);
        auto it = pending_by_session_id_.find(std::string(session_id));
        if (it != pending_by_session_id_.end()) {
            agent_id = it->second.agent_id;
        }
    }
    if (agent_id.empty()) {
        // Try the registry directly
        auto session = registry_.find_by_session(session_id);
        if (session) {
            agent_id = session->agent_id;
        }
    }

    if (agent_id.empty()) {
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "unknown session");
    }

    // Store health snapshot and update session activity timestamp
    if (health_store_) {
        health_store_->upsert(agent_id, request->status_tags());
    }
    registry_.touch_activity(agent_id);
    metrics_.counter("yuzu_heartbeats_received_total", {{"via", "direct"}}).increment();

    response->set_acknowledged(true);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
    response->mutable_server_time()->set_millis_epoch(now_ms);

    spdlog::debug("Heartbeat from agent={} (session={})", agent_id, session_id);
    return grpc::Status::OK;
}

// -- Subscribe ----------------------------------------------------------------

grpc::Status AgentServiceImpl::Subscribe(
    grpc::ServerContext* context,
    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) {
    if (!context) {
        return grpc::Status(grpc::StatusCode::INTERNAL, "missing server context");
    }

    const auto session_id = client_metadata_value(*context, kSessionMetadataKey);
    if (session_id.empty()) {
        spdlog::warn("Subscribe rejected: missing {} metadata", kSessionMetadataKey);
        return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, "missing session metadata");
    }

    std::string agent_id;
    {
        std::lock_guard lock(pending_mu_);
        prune_expired_pending_locked();
        auto it = pending_by_session_id_.find(session_id);
        if (it == pending_by_session_id_.end()) {
            spdlog::warn("Subscribe rejected: unknown or expired session id");
            return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                                "invalid or expired session");
        }

        if (!gateway_mode_ && it->second.register_peer != context->peer()) {
            spdlog::warn("Subscribe rejected: peer mismatch for session {}", session_id);
            return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "peer mismatch");
        }

        if (require_client_identity_) {
            const auto subscribe_ids = extract_peer_identities(*context);
            if (!has_identity_overlap(it->second.peer_identities, subscribe_ids)) {
                spdlog::warn("Subscribe rejected: mTLS identity mismatch for session {}",
                             session_id);
                return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "peer identity mismatch");
            }
        }

        agent_id = it->second.agent_id;
        pending_by_session_id_.erase(it);
    }

    spdlog::info("Agent subscribe stream opened for {}", agent_id);
    registry_.set_stream(agent_id, stream, context);
    registry_.map_session(session_id, agent_id);

    auto subscribe_start = std::chrono::steady_clock::now();
    if (analytics_store_) {
        AnalyticsEvent ae;
        ae.event_type = "agent.connected";
        ae.agent_id = agent_id;
        ae.session_id = session_id;
        ae.attributes = {{"via", "direct"}};
        analytics_store_->emit(std::move(ae));
    }

    // Read loop -- process responses from the agent
    pb::CommandResponse resp;
    while (stream->Read(&resp)) {
        registry_.touch_activity(agent_id);
        if (resp.status() == pb::CommandResponse::RUNNING) {
            // Intercept __timing__ metadata
            if (resp.output().starts_with("__timing__|")) {
                auto payload = resp.output().substr(11);
                auto eq = payload.find('=');
                auto ms = (eq != std::string::npos) ? payload.substr(eq + 1) : payload;
                bus_.publish("timing", "<strong id=\"stat-agent\" hx-swap-oob=\"true\">" +
                                           html_escape(ms) + " ms</strong>");
                continue;
            }

            // Track first response for server-side latency
            {
                std::lock_guard lock(cmd_times_mu_);
                if (!cmd_first_seen_.contains(resp.command_id())) {
                    cmd_first_seen_.insert(resp.command_id());
                    auto it = cmd_send_times_.find(resp.command_id());
                    if (it != cmd_send_times_.end()) {
                        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                           std::chrono::steady_clock::now() - it->second)
                                           .count();
                        bus_.publish("timing", "<strong id=\"stat-network\" hx-swap-oob=\"true\">" +
                                                   std::to_string(elapsed) + " ms</strong>");
                    }
                }
            }

            // Determine the plugin from command_id prefix (format: plugin-timestamp)
            std::string plugin = extract_plugin(resp.command_id());

            // Publish each row as its own SSE event
            publish_output_rows(agent_id, plugin, resp.output());

            // Store streaming response
            if (response_store_) {
                StoredResponse sr;
                sr.instruction_id = resp.command_id();
                sr.agent_id = agent_id;
                sr.status = static_cast<int>(resp.status());
                sr.output = resp.output();
                sr.plugin = plugin;
                // PR 2: stamp execution_id from the dispatch-time mapping so
                // the executions detail drawer can correlate exactly.
                {
                    std::lock_guard lock(cmd_times_mu_);
                    if (auto eit = cmd_execution_ids_.find(resp.command_id());
                        eit != cmd_execution_ids_.end()) {
                        sr.execution_id = eit->second;
                    }
                }
                response_store_->store(sr);
            }

            // UAT 2026-05-06 #8: notify the executions tracker so the
            // drawer's per-agent KPI table populates and the SSE
            // `agent-transition` event fires for live updates.
            notify_exec_tracker(resp.command_id(), agent_id, resp);

            if (analytics_store_) {
                AnalyticsEvent ae;
                ae.event_type = "command.response";
                ae.agent_id = agent_id;
                ae.plugin = plugin;
                ae.correlation_id = resp.command_id();
                ae.payload = {{"output_bytes", resp.output().size()}};
                analytics_store_->emit(std::move(ae));
            }

        } else {
            spdlog::info("Command {} completed: status={}, exit_code={}", resp.command_id(),
                         static_cast<int>(resp.status()), resp.exit_code());

            // Store completion response
            if (response_store_) {
                auto plugin_name = extract_plugin(resp.command_id());
                std::string err_detail;
                if (resp.has_error()) {
                    err_detail = resp.error().message();
                }
                // PR 2: resolve execution_id from the dispatch-time mapping.
                // Do NOT erase on terminal status — a single command_id
                // can produce N terminal responses (one per agent in
                // fan-out); erasing on the first agent's terminal would
                // cause agents 2..N to stamp empty execution_id (HF-1).
                // Map entries persist until a future sweeper (PR 2.x).
                std::string current_exec;
                {
                    std::lock_guard lock(cmd_times_mu_);
                    if (auto eit = cmd_execution_ids_.find(resp.command_id());
                        eit != cmd_execution_ids_.end()) {
                        current_exec = eit->second;
                    }
                }
                // Terminal frame with no output: update the existing
                // RUNNING rows in place — the data is already there.
                // Persisting an empty-output row whose status enum reads
                // to operators as a failure exit code was the cause of
                // the spurious "exit=1 then exit=0" pair (UAT 2026-05-06).
                bool finalized = false;
                if (resp.output().empty()) {
                    finalized = response_store_->finalize_terminal_status(
                        resp.command_id(), agent_id, static_cast<int>(resp.status()), err_detail,
                        current_exec);
                }
                if (!finalized) {
                    // No prior RUNNING row (terminal-only command) or the
                    // terminal frame carries output — insert as before.
                    StoredResponse sr;
                    sr.instruction_id = resp.command_id();
                    sr.agent_id = agent_id;
                    sr.status = static_cast<int>(resp.status());
                    sr.output = resp.output();
                    sr.plugin = plugin_name;
                    sr.error_detail = err_detail;
                    sr.execution_id = current_exec;
                    response_store_->store(sr);
                }
            }

            // UAT 2026-05-06 #8: notify the executions tracker on terminal
            // status so the drawer's per-agent KPI flips to its terminal
            // state and the SSE `agent-transition` event fires.
            notify_exec_tracker(resp.command_id(), agent_id, resp);

            std::string status_str =
                (resp.status() == pb::CommandResponse::SUCCESS) ? "done" : "error";
            metrics_.counter("yuzu_commands_completed_total", {{"status", status_str}}).increment();
            {
                std::string badge_cls = (status_str == "done") ? "badge-done" : "badge-error";
                std::string badge_text = (status_str == "done") ? "DONE" : "ERROR";
                bus_.publish("command-status", "<span id=\"status-badge\" class=\"" + badge_cls +
                                                   "\" hx-swap-oob=\"outerHTML\">" + badge_text +
                                                   "</span>");
            }

            if (analytics_store_) {
                AnalyticsEvent ae;
                ae.event_type = "command.completed";
                ae.agent_id = agent_id;
                ae.plugin = extract_plugin(resp.command_id());
                ae.correlation_id = resp.command_id();
                ae.severity = (resp.status() == pb::CommandResponse::SUCCESS) ? Severity::kInfo
                                                                              : Severity::kError;
                ae.payload = {{"status", status_str}, {"exit_code", resp.exit_code()}};
                if (resp.has_error()) {
                    ae.payload["error_message"] = resp.error().message();
                }
                analytics_store_->emit(std::move(ae));
            }

            // Create notification on execution failure
            if (resp.status() != pb::CommandResponse::SUCCESS && notification_store_ &&
                notification_store_->is_open()) {
                std::string err_msg = resp.has_error() ? resp.error().message() : "unknown";
                notification_store_->create("error", "Execution Failed",
                                            "Command " + resp.command_id() + " on agent " +
                                                agent_id + " failed: " + err_msg);
            }

            // Fire webhook + offload on execution completion. Each sink is
            // guarded independently — one sink null/closed must not silence
            // the other (HP-1 / UP-6). Single serialise per response (perf-S1).
            if ((webhook_store_ && webhook_store_->is_open()) ||
                (offload_target_store_ && offload_target_store_->is_open())) {
                nlohmann::json wh_payload = {{"event", "execution.completed"},
                                             {"command_id", resp.command_id()},
                                             {"agent_id", agent_id},
                                             {"status", status_str},
                                             {"exit_code", resp.exit_code()}};
                if (resp.has_error()) {
                    wh_payload["error"] = resp.error().message();
                }
                const auto body = wh_payload.dump();
                if (webhook_store_ && webhook_store_->is_open()) {
                    webhook_store_->fire_event("execution.completed", body);
                }
                if (offload_target_store_ && offload_target_store_->is_open()) {
                    offload_target_store_->fire_event("execution.completed", body);
                }
            }

            // Publish total round-trip and clean up timing maps
            {
                std::lock_guard lock(cmd_times_mu_);
                auto it = cmd_send_times_.find(resp.command_id());
                if (it != cmd_send_times_.end()) {
                    auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::steady_clock::now() - it->second)
                                        .count();
                    metrics_.histogram("yuzu_command_duration_seconds")
                        .observe(static_cast<double>(total_ms) / 1000.0);
                    bus_.publish("timing", "<strong id=\"stat-total\" hx-swap-oob=\"true\">" +
                                               std::to_string(total_ms) + " ms</strong>");
                    cmd_send_times_.erase(it);
                }
                cmd_first_seen_.erase(resp.command_id());
            }
        }
    }

    // Agent disconnected — use session-aware cleanup so a stale Subscribe
    // handler doesn't clobber a newer connection from the same agent_id.
    registry_.clear_stream_if_session(agent_id, session_id);
    registry_.remove_agent_if_session(agent_id, session_id);
    spdlog::info("Agent subscribe stream closed for {} (session={})", agent_id, session_id);

    if (analytics_store_) {
        auto session_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now() - subscribe_start)
                                    .count();
        AnalyticsEvent ae;
        ae.event_type = "agent.disconnected";
        ae.agent_id = agent_id;
        ae.session_id = session_id;
        ae.payload = {{"session_duration_ms", session_duration}};
        analytics_store_->emit(std::move(ae));
    }

    return grpc::Status::OK;
}

// -- record_send_time ---------------------------------------------------------

void AgentServiceImpl::record_send_time(const std::string& command_id) {
    std::lock_guard lock(cmd_times_mu_);
    cmd_send_times_[command_id] = std::chrono::steady_clock::now();
    output_row_count_.store(0, std::memory_order_relaxed);
}

// -- record_execution_id (PR 2) -----------------------------------------------

void AgentServiceImpl::record_execution_id(const std::string& command_id,
                                           const std::string& execution_id) {
    std::lock_guard lock(cmd_times_mu_);
    if (execution_id.empty()) {
        cmd_execution_ids_.erase(command_id);
    } else {
        cmd_execution_ids_[command_id] = execution_id;
    }
}

// -- process_gateway_response -------------------------------------------------

void AgentServiceImpl::process_gateway_response(const std::string& agent_id,
                                                const pb::CommandResponse& resp) {
    if (resp.status() == pb::CommandResponse::RUNNING) {
        // Intercept __timing__ metadata
        if (resp.output().starts_with("__timing__|")) {
            auto payload = resp.output().substr(11);
            auto eq = payload.find('=');
            auto ms = (eq != std::string::npos) ? payload.substr(eq + 1) : payload;
            bus_.publish("timing", "<strong id=\"stat-agent\" hx-swap-oob=\"true\">" +
                                       html_escape(ms) + " ms</strong>");
            return;
        }

        // Track first response for server-side latency
        {
            std::lock_guard lock(cmd_times_mu_);
            if (!cmd_first_seen_.contains(resp.command_id())) {
                cmd_first_seen_.insert(resp.command_id());
                auto it = cmd_send_times_.find(resp.command_id());
                if (it != cmd_send_times_.end()) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       std::chrono::steady_clock::now() - it->second)
                                       .count();
                    bus_.publish("timing", "<strong id=\"stat-network\" hx-swap-oob=\"true\">" +
                                               std::to_string(elapsed) + " ms</strong>");
                }
            }
        }

        std::string plugin = extract_plugin(resp.command_id());
        publish_output_rows(agent_id, plugin, resp.output());

        if (response_store_) {
            StoredResponse sr;
            sr.instruction_id = resp.command_id();
            sr.agent_id = agent_id;
            sr.status = static_cast<int>(resp.status());
            sr.output = resp.output();
            sr.plugin = plugin;
            // PR 2: streaming response — keep the mapping until completion.
            {
                std::lock_guard lock(cmd_times_mu_);
                if (auto eit = cmd_execution_ids_.find(resp.command_id());
                    eit != cmd_execution_ids_.end()) {
                    sr.execution_id = eit->second;
                }
            }
            response_store_->store(sr);
        }

        // UAT 2026-05-06 #8: gateway-streamed RUNNING — notify tracker.
        notify_exec_tracker(resp.command_id(), agent_id, resp);

        if (analytics_store_) {
            AnalyticsEvent ae;
            ae.event_type = "command.response";
            ae.agent_id = agent_id;
            ae.plugin = plugin;
            ae.correlation_id = resp.command_id();
            ae.payload = {{"output_bytes", resp.output().size()}};
            analytics_store_->emit(std::move(ae));
        }
    } else {
        spdlog::info("[gateway] Command {} completed: status={}, exit_code={}", resp.command_id(),
                     static_cast<int>(resp.status()), resp.exit_code());

        if (response_store_) {
            auto gw_plugin = extract_plugin(resp.command_id());
            std::string err_detail;
            if (resp.has_error()) {
                err_detail = resp.error().message();
            }
            // PR 2: stamp execution_id from the dispatch-time mapping.
            // Do NOT erase on terminal status (HF-1) — multi-agent
            // fan-out produces N terminal responses; entries persist
            // until a future sweeper (PR 2.x) lands.
            std::string current_exec;
            {
                std::lock_guard lock(cmd_times_mu_);
                if (auto eit = cmd_execution_ids_.find(resp.command_id());
                    eit != cmd_execution_ids_.end()) {
                    current_exec = eit->second;
                }
            }
            // Terminal frame with no output: update existing RUNNING row(s)
            // instead of inserting a separate empty-output sentinel that
            // operators misread as a failure (UAT 2026-05-06).
            bool finalized = false;
            if (resp.output().empty()) {
                finalized = response_store_->finalize_terminal_status(
                    resp.command_id(), agent_id, static_cast<int>(resp.status()), err_detail,
                    current_exec);
            }
            if (!finalized) {
                StoredResponse sr;
                sr.instruction_id = resp.command_id();
                sr.agent_id = agent_id;
                sr.status = static_cast<int>(resp.status());
                sr.output = resp.output();
                sr.plugin = gw_plugin;
                sr.error_detail = err_detail;
                sr.execution_id = current_exec;
                response_store_->store(sr);
            }
        }

        // UAT 2026-05-06 #8: gateway-streamed terminal — notify tracker.
        notify_exec_tracker(resp.command_id(), agent_id, resp);

        std::string status_str = (resp.status() == pb::CommandResponse::SUCCESS) ? "done" : "error";
        metrics_.counter("yuzu_commands_completed_total", {{"status", status_str}}).increment();
        {
            std::string badge_cls = (status_str == "done") ? "badge-done" : "badge-error";
            std::string badge_text = (status_str == "done") ? "DONE" : "ERROR";
            bus_.publish("command-status", "<span id=\"status-badge\" class=\"" + badge_cls +
                                               "\" hx-swap-oob=\"outerHTML\">" + badge_text +
                                               "</span>");
        }

        if (analytics_store_) {
            AnalyticsEvent ae;
            ae.event_type = "command.completed";
            ae.agent_id = agent_id;
            ae.plugin = extract_plugin(resp.command_id());
            ae.correlation_id = resp.command_id();
            ae.severity = (resp.status() == pb::CommandResponse::SUCCESS) ? Severity::kInfo
                                                                          : Severity::kError;
            ae.payload = {{"status", status_str}, {"exit_code", resp.exit_code()}};
            if (resp.has_error()) {
                ae.payload["error_message"] = resp.error().message();
            }
            analytics_store_->emit(std::move(ae));
        }

        if (resp.status() != pb::CommandResponse::SUCCESS && notification_store_ &&
            notification_store_->is_open()) {
            std::string err_msg = resp.has_error() ? resp.error().message() : "unknown";
            notification_store_->create("error", "Execution Failed",
                                        "Command " + resp.command_id() + " on agent " + agent_id +
                                            " failed: " + err_msg);
        }

        if ((webhook_store_ && webhook_store_->is_open()) ||
            (offload_target_store_ && offload_target_store_->is_open())) {
            nlohmann::json wh_payload = {{"event", "execution.completed"},
                                         {"command_id", resp.command_id()},
                                         {"agent_id", agent_id},
                                         {"status", status_str},
                                         {"exit_code", resp.exit_code()}};
            if (resp.has_error()) {
                wh_payload["error"] = resp.error().message();
            }
            const auto body = wh_payload.dump();
            if (webhook_store_ && webhook_store_->is_open()) {
                webhook_store_->fire_event("execution.completed", body);
            }
            if (offload_target_store_ && offload_target_store_->is_open()) {
                offload_target_store_->fire_event("execution.completed", body);
            }
        }

        // Publish total round-trip and clean up timing maps
        {
            std::lock_guard lock(cmd_times_mu_);
            auto it = cmd_send_times_.find(resp.command_id());
            if (it != cmd_send_times_.end()) {
                auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now() - it->second)
                                    .count();
                metrics_.histogram("yuzu_command_duration_seconds")
                    .observe(static_cast<double>(total_ms) / 1000.0);
                bus_.publish("timing", "<strong id=\"stat-total\" hx-swap-oob=\"true\">" +
                                           std::to_string(total_ms) + " ms</strong>");
                cmd_send_times_.erase(it);
            }
            cmd_first_seen_.erase(resp.command_id());
        }
    }
}

// -- SSE row helpers ----------------------------------------------------------
// Parsing utilities are in result_parsing.hpp.  Thin delegators kept here for
// API compatibility (thead_for_plugin is called from server.cpp).

std::string AgentServiceImpl::thead_for_plugin(const std::string& plugin) {
    auto& cols = yuzu::server::columns_for_plugin(plugin);
    std::string html = "<tr>";
    for (size_t i = 0; i < cols.size(); ++i) {
        html += (i == 0) ? "<th class=\"col-agent\">" : "<th>";
        html += html_escape(cols[i]);
        html += "</th>";
    }
    html += "</tr>";
    return html;
}

std::string AgentServiceImpl::render_row(const std::string& agent_name, const std::string& plugin,
                                         const std::string& line,
                                         const std::vector<std::string>& col_names) {
    auto fields = yuzu::server::split_fields(plugin, line);

    // Build cells: agent_name + fields
    std::vector<std::string> cells;
    cells.reserve(fields.size() + 1);
    cells.push_back(agent_name);
    for (auto& f : fields)
        cells.push_back(f);

    // Data row
    std::string html = "<tr class=\"result-row\" onclick=\"toggleDetail(this)\">";
    for (size_t i = 0; i < cells.size(); ++i) {
        auto esc = html_escape(cells[i]);
        html += (i == 0) ? "<td class=\"col-agent\" title=\"" : "<td title=\"";
        html += esc;
        html += "\">";
        html += esc;
        html += "</td>";
    }
    html += "</tr>";

    // Detail drawer
    html += "<tr class=\"result-detail\"><td colspan=\"";
    html += std::to_string(cells.size());
    html += "\"><div class=\"detail-content\">";
    for (size_t i = 0; i < cells.size(); ++i) {
        auto label = (i < col_names.size()) ? col_names[i] : ("Column " + std::to_string(i + 1));
        html += "<div class=\"detail-label\">" + html_escape(label) + "</div>";
        html += "<div class=\"detail-value\">" + html_escape(cells[i]) + "</div>";
    }
    html += "</div></td></tr>";
    return html;
}

void AgentServiceImpl::notify_exec_tracker(const std::string& command_id,
                                           const std::string& agent_id,
                                           const pb::CommandResponse& resp) {
    if (!execution_tracker_)
        return;
    std::string execution_id;
    {
        std::lock_guard lock(cmd_times_mu_);
        if (auto eit = cmd_execution_ids_.find(command_id); eit != cmd_execution_ids_.end()) {
            execution_id = eit->second;
        }
    }
    if (execution_id.empty())
        return; // out-of-band dispatch, nothing to publish

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

    AgentExecStatus s;
    s.agent_id = agent_id;
    s.dispatched_at = 0; // upsert keeps prior value if non-zero
    s.exit_code = resp.exit_code();
    if (resp.has_error()) {
        s.error_detail = resp.error().message();
    }
    switch (resp.status()) {
    case pb::CommandResponse::RUNNING:
        s.status = "running";
        s.first_response_at = now;
        s.completed_at = 0;
        break;
    case pb::CommandResponse::SUCCESS:
        s.status = "success";
        s.first_response_at = now;
        s.completed_at = now;
        break;
    case pb::CommandResponse::FAILURE:
        s.status = "failure";
        s.first_response_at = now;
        s.completed_at = now;
        break;
    case pb::CommandResponse::TIMEOUT:
        s.status = "timeout";
        s.first_response_at = now;
        s.completed_at = now;
        break;
    case pb::CommandResponse::REJECTED:
        s.status = "rejected";
        s.first_response_at = 0;
        s.completed_at = now;
        break;
    default:
        return;
    }
    execution_tracker_->update_agent_status(execution_id, s);
}

void AgentServiceImpl::publish_output_rows(const std::string& agent_id, const std::string& plugin,
                                           const std::string& raw_output) {
    if (raw_output.empty())
        return;
    auto agent_name = registry_.display_name(agent_id);
    auto& col_names = yuzu::server::columns_for_plugin(plugin);
    auto lines = yuzu::server::split_output_lines(raw_output);
    for (const auto& line : lines) {
        // TAR warehouse protocol lines: __schema__ and __total__
        if (plugin == "tar" && yuzu::server::is_tar_protocol_line(line)) {
            if (line.starts_with("__schema__|")) {
                auto cols = yuzu::server::parse_tar_schema_line(line);
                // M16: Validate schema line has non-empty columns
                if (cols.empty())
                    continue;
                // H14: Thread-safe per-instance cache with mutex
                {
                    std::lock_guard lock(cmd_times_mu_);
                    tar_dynamic_columns_ = cols;
                }
                // C1: HTML-escape column names to prevent XSS via AS aliases
                std::string thead = "<thead id=\"results-thead\" hx-swap-oob=\"true\"><tr>"
                                    "<th class=\"col-agent\">Agent</th>";
                for (const auto& c : cols) {
                    thead += "<th>";
                    // Escape HTML special characters
                    for (char ch : c) {
                        switch (ch) {
                        case '<':
                            thead += "&lt;";
                            break;
                        case '>':
                            thead += "&gt;";
                            break;
                        case '&':
                            thead += "&amp;";
                            break;
                        case '"':
                            thead += "&quot;";
                            break;
                        case '\'':
                            thead += "&#39;";
                            break;
                        default:
                            thead += ch;
                            break;
                        }
                    }
                    thead += "</th>";
                }
                thead += "</tr></thead>";
                bus_.publish("output", thead);
            }
            continue;
        }

        // Use dynamic columns for TAR SQL results if available (H14: lock)
        std::vector<std::string> tar_cols_copy;
        {
            std::lock_guard lock(cmd_times_mu_);
            tar_cols_copy = tar_dynamic_columns_;
        }
        auto& effective_cols =
            (!tar_cols_copy.empty() && plugin == "tar") ? tar_cols_copy : col_names;

        auto count = output_row_count_.fetch_add(1, std::memory_order_relaxed) + 1;
        auto row_html = render_row(agent_name, plugin, line, effective_cols);

        // All elements must be OOB-targeted — the SSE sink uses
        // hx-swap="none".  Mixing <tr> and <span> in a single
        // fragment breaks under the browser's table content model
        // (foster parenting ejects non-table elements, losing the
        // swap target).
        std::string html;
        // OOB: append rows to results tbody
        html += "<tbody id=\"results-tbody\" hx-swap-oob=\"beforeend\">";
        html += row_html;
        html += "</tbody>";
        // OOB: live row count
        html += "<span id=\"row-count\" hx-swap-oob=\"true\">";
        html += std::to_string(count);
        html += "</span>";
        // OOB: remove empty-state placeholder on first row only
        if (count == 1)
            html += "<tr id=\"empty-row\" hx-swap-oob=\"delete\"></tr>";
        bus_.publish("output", html);
    }
}

// -- OTA Update RPCs ----------------------------------------------------------

grpc::Status AgentServiceImpl::CheckForUpdate(grpc::ServerContext* /*context*/,
                                              const pb::CheckForUpdateRequest* request,
                                              pb::CheckForUpdateResponse* response) {
    metrics_
        .counter("yuzu_grpc_requests_total", {{"method", "CheckForUpdate"}, {"status", "received"}})
        .increment();

    if (!update_registry_) {
        response->set_update_available(false);
        return grpc::Status::OK;
    }

    auto latest =
        update_registry_->latest_for(request->platform().os(), request->platform().arch());

    if (!latest) {
        response->set_update_available(false);
        return grpc::Status::OK;
    }

    // Compare: if agent already has latest or newer, no update
    if (compare_versions(latest->version, request->current_version()) <= 0) {
        response->set_update_available(false);
        return grpc::Status::OK;
    }

    bool eligible = UpdateRegistry::is_eligible(request->agent_id(), latest->rollout_pct);

    response->set_update_available(true);
    response->set_latest_version(latest->version);
    response->set_sha256(latest->sha256);
    response->set_mandatory(latest->mandatory);
    response->set_eligible(eligible);
    response->set_file_size(latest->file_size);

    spdlog::info("CheckForUpdate: agent {} v{} -> v{} (eligible={}, mandatory={})",
                 request->agent_id(), request->current_version(), latest->version, eligible,
                 latest->mandatory);
    return grpc::Status::OK;
}

grpc::Status AgentServiceImpl::DownloadUpdate(grpc::ServerContext* /*context*/,
                                              const pb::DownloadUpdateRequest* request,
                                              grpc::ServerWriter<pb::DownloadUpdateChunk>* writer) {
    metrics_
        .counter("yuzu_grpc_requests_total", {{"method", "DownloadUpdate"}, {"status", "received"}})
        .increment();

    if (!update_registry_) {
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, "OTA not configured");
    }

    auto pkg = update_registry_->latest_for(request->platform().os(), request->platform().arch());
    if (!pkg || pkg->version != request->version()) {
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "version not found");
    }

    auto file_path = update_registry_->binary_path(*pkg);
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        spdlog::error("DownloadUpdate: binary file missing: {}", file_path.string());
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "binary file missing");
    }

    constexpr std::size_t kChunkSize = 64 * 1024; // 64KB
    std::vector<char> buffer(kChunkSize);
    int64_t offset = 0;

    while (file.read(buffer.data(), static_cast<std::streamsize>(kChunkSize)) ||
           file.gcount() > 0) {
        pb::DownloadUpdateChunk chunk;
        chunk.set_data(buffer.data(), static_cast<std::size_t>(file.gcount()));
        chunk.set_offset(offset);
        chunk.set_total_size(pkg->file_size);

        if (!writer->Write(chunk)) {
            spdlog::warn("DownloadUpdate: client disconnected at offset {}", offset);
            return grpc::Status::CANCELLED;
        }

        offset += file.gcount();
    }

    spdlog::info("DownloadUpdate: sent {} bytes of v{} to agent {}", offset, pkg->version,
                 request->agent_id());
    return grpc::Status::OK;
}

// -- Private helpers ----------------------------------------------------------

std::vector<std::string>
AgentServiceImpl::extract_peer_identities(const grpc::ServerContext& context) {
    std::vector<std::string> out;
    auto auth_ctx = context.auth_context();
    if (!auth_ctx || !auth_ctx->IsPeerAuthenticated()) {
        return out;
    }

    auto append_unique = [&out](std::string_view s) {
        if (s.empty())
            return;
        for (const auto& existing : out) {
            if (existing == s)
                return;
        }
        out.emplace_back(s);
    };

    for (const auto& id : auth_ctx->GetPeerIdentity()) {
        append_unique(std::string_view{id.data(), id.size()});
    }
    for (const auto& cn : auth_ctx->FindPropertyValues(GRPC_X509_CN_PROPERTY_NAME)) {
        append_unique(std::string_view{cn.data(), cn.size()});
    }
    for (const auto& san : auth_ctx->FindPropertyValues(GRPC_X509_SAN_PROPERTY_NAME)) {
        append_unique(std::string_view{san.data(), san.size()});
    }

    return out;
}

bool AgentServiceImpl::peer_identity_matches_agent_id(const grpc::ServerContext& context,
                                                      const std::string& agent_id) {
    if (agent_id.empty())
        return false;
    const auto identities = extract_peer_identities(context);
    for (const auto& id : identities) {
        if (id == agent_id)
            return true;
    }
    return false;
}

std::string AgentServiceImpl::client_metadata_value(const grpc::ServerContext& context,
                                                    std::string_view key) {
    const auto& md = context.client_metadata();
    auto it = md.find(std::string(key));
    if (it == md.end())
        return {};
    return std::string(it->second.data(), it->second.length());
}

bool AgentServiceImpl::has_identity_overlap(const std::vector<std::string>& lhs,
                                            const std::vector<std::string>& rhs) {
    for (const auto& left : lhs) {
        for (const auto& right : rhs) {
            if (left == right)
                return true;
        }
    }
    return false;
}

void AgentServiceImpl::prune_expired_pending_locked() {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = pending_by_session_id_.begin(); it != pending_by_session_id_.end();) {
        if (now - it->second.created_at > kPendingRegistrationTtl) {
            it = pending_by_session_id_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string AgentServiceImpl::extract_plugin(const std::string& command_id) {
    auto dash = command_id.find('-');
    if (dash != std::string::npos) {
        return command_id.substr(0, dash);
    }
    return command_id;
}

} // namespace yuzu::server::detail
