#include <yuzu/metrics.hpp>
#include <yuzu/secure_zero.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include "agent.grpc.pb.h"
#include "analytics_event.hpp"
#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "data_export.hpp"
#include "execution_tracker.hpp"
#include "gateway.grpc.pb.h"
#include "instruction_store.hpp"
#include "management.grpc.pb.h"
#include "management_group_store.hpp"
#include "nvd_db.hpp"
#include "policy_store.hpp"
#include "nvd_sync.hpp"
#include "oidc_provider.hpp"
#include "quarantine_store.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "rest_api_v1.hpp"
#include "schedule_engine.hpp"
#include "scope_engine.hpp"
#include "tag_store.hpp"
#include "update_registry.hpp"

#include <grpc/grpc_security_constants.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <ranges>
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
extern const char* const kInstructionEditorHtml;
extern const char* const kInstructionEditorDeniedHtml;

// Compliance dashboard page (compliance_ui.cpp).
extern const char* const kComplianceHtml;

// Shared design system assets (css_bundle.cpp, icons_svg.cpp).
extern const char* const kYuzuCss;
extern const char* const kYuzuIconsSvg;

namespace yuzu::server {

namespace detail {

namespace pb = ::yuzu::agent::v1;
namespace gw = ::yuzu::gateway::v1;

// -- Platform-specific log path -----------------------------------------------

[[nodiscard]] std::filesystem::path server_log_path() {
#ifdef _WIN32
    return R"(C:\ProgramData\Yuzu\logs\agent.log)";
#elif defined(__APPLE__)
    if (const char* home = std::getenv("HOME")) {
        return std::filesystem::path(home) / "Library/Logs/Yuzu/server.log";
    }
    return "/Library/Logs/Yuzu/server.log";
#else
    return "/var/log/yuzu/server.log";
#endif
}

// -- SSE Event ----------------------------------------------------------------

struct SseEvent {
    std::string event_type;
    std::string data;
};

// -- SSE Event Bus ------------------------------------------------------------

class EventBus {
public:
    using Listener = std::function<void(const SseEvent&)>;

    std::size_t subscribe(Listener fn) {
        std::lock_guard<std::mutex> lock(mu_);
        auto id = next_id_++;
        listeners_[id] = std::move(fn);
        return id;
    }

    void unsubscribe(std::size_t id) {
        std::lock_guard<std::mutex> lock(mu_);
        listeners_.erase(id);
    }

    void publish(const std::string& event_type, const std::string& data) {
        SseEvent ev{event_type, data};
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& [id, fn] : listeners_) {
            fn(ev);
        }
    }

private:
    std::mutex mu_;
    std::size_t next_id_ = 0;
    std::unordered_map<std::size_t, Listener> listeners_;
};

// -- Agent session (one per connected agent) ----------------------------------

struct PluginMeta {
    std::string name;
    std::string version;
    std::string description;
    std::vector<std::string> actions;
};

struct AgentSession {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::string arch;
    std::string agent_version;
    std::vector<std::string> plugin_names;
    std::vector<PluginMeta> plugin_meta;
    std::unordered_map<std::string, std::string> scopable_tags;

    // Stream pointer — valid only while Subscribe() RPC is active.
    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream = nullptr;
    std::mutex stream_mu;
};

// -- Agent registry -----------------------------------------------------------

class AgentRegistry {
public:
    explicit AgentRegistry(EventBus& bus, yuzu::MetricsRegistry& metrics)
        : bus_(bus), metrics_(metrics) {}

    void register_agent(const pb::AgentInfo& info) {
        auto session = std::make_shared<AgentSession>();
        session->agent_id = info.agent_id();
        session->hostname = info.hostname();
        session->os = info.platform().os();
        session->arch = info.platform().arch();
        session->agent_version = info.agent_version();
        for (const auto& [k, v] : info.scopable_tags()) {
            session->scopable_tags[k] = v;
        }
        for (const auto& p : info.plugins()) {
            session->plugin_names.push_back(p.name());
            PluginMeta pm;
            pm.name = p.name();
            pm.version = p.version();
            pm.description = p.description();
            for (const auto& cap : p.capabilities()) {
                pm.actions.push_back(cap);
            }
            session->plugin_meta.push_back(std::move(pm));
        }

        {
            std::lock_guard lock(mu_);
            agents_[info.agent_id()] = session;
        }
        metrics_.counter("yuzu_agents_registered_total").increment();
        metrics_.gauge("yuzu_agents_connected").set(static_cast<double>(agent_count()));
        bus_.publish("agent-online", info.agent_id());
        spdlog::info("Agent registered: id={}, hostname={}, plugins={}", info.agent_id(),
                     info.hostname(), info.plugins_size());
    }

    void set_stream(const std::string& agent_id,
                    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it != agents_.end()) {
            std::lock_guard slock(it->second->stream_mu);
            it->second->stream = stream;
        }
    }

    void clear_stream(const std::string& agent_id) {
        std::shared_ptr<AgentSession> session;
        {
            std::lock_guard lock(mu_);
            auto it = agents_.find(agent_id);
            if (it == agents_.end())
                return;
            session = it->second;
        }
        {
            std::lock_guard slock(session->stream_mu);
            session->stream = nullptr;
        }
    }

    void remove_agent(const std::string& agent_id) {
        {
            std::lock_guard lock(mu_);
            agents_.erase(agent_id);
        }
        metrics_.gauge("yuzu_agents_connected").set(static_cast<double>(agent_count()));
        bus_.publish("agent-offline", agent_id);
        spdlog::info("Agent removed: id={}", agent_id);
    }

    // Send a command to a specific agent. Returns false if agent not found or write failed.
    bool send_to(const std::string& agent_id, const pb::CommandRequest& cmd) {
        std::shared_ptr<AgentSession> session;
        {
            std::lock_guard lock(mu_);
            auto it = agents_.find(agent_id);
            if (it == agents_.end())
                return false;
            session = it->second;
        }
        std::lock_guard slock(session->stream_mu);
        if (!session->stream)
            return false;
        return session->stream->Write(cmd, grpc::WriteOptions());
    }

    // Send command to all connected agents. Returns count of agents sent to.
    int send_to_all(const pb::CommandRequest& cmd) {
        std::vector<std::shared_ptr<AgentSession>> snapshot;
        {
            std::lock_guard lock(mu_);
            snapshot.reserve(agents_.size());
            for (auto& s : agents_ | std::views::values) {
                snapshot.push_back(s);
            }
        }
        int count = 0;
        for (auto& s : snapshot) {
            std::lock_guard slock(s->stream_mu);
            if (s->stream && s->stream->Write(cmd, grpc::WriteOptions())) {
                ++count;
            }
        }
        return count;
    }

    bool has_any() const {
        std::lock_guard lock(mu_);
        return !agents_.empty();
    }

    // Build JSON array of all agents for the web UI.
    std::string to_json() const {
        std::lock_guard lock(mu_);

        nlohmann::json arr = nlohmann::json::array();
        for (const auto& s : agents_ | std::views::values) {
            arr.push_back({{"agent_id", s->agent_id},
                           {"hostname", s->hostname},
                           {"os", s->os},
                           {"arch", s->arch},
                           {"agent_version", s->agent_version}});
        }
        return arr.dump();
    }

    // Build help catalog: deduplicated plugin metadata across all agents.
    std::string help_json() const {
        std::lock_guard lock(mu_);

        // Deduplicate plugins by name (take the richest action list)
        std::unordered_map<std::string, const PluginMeta*> best;
        for (const auto& s : agents_ | std::views::values) {
            for (const auto& pm : s->plugin_meta) {
                auto it = best.find(pm.name);
                if (it == best.end() || pm.actions.size() > it->second->actions.size()) {
                    best[pm.name] = &pm;
                }
            }
        }

        // Sort by plugin name
        std::vector<const PluginMeta*> sorted;
        sorted.reserve(best.size());
        for (const auto* pm : best | std::views::values)
            sorted.push_back(pm);
        std::ranges::sort(
            sorted, [](const PluginMeta* a, const PluginMeta* b) { return a->name < b->name; });

        nlohmann::json plugins_arr = nlohmann::json::array();
        nlohmann::json commands_arr = nlohmann::json::array();

        for (const auto* pm : sorted) {
            nlohmann::json pj;
            pj["name"] = pm->name;
            pj["version"] = pm->version;
            pj["description"] = pm->description;
            pj["actions"] = pm->actions;

            plugins_arr.push_back(std::move(pj));

            // Build command strings: bare plugin name + plugin action
            commands_arr.push_back(pm->name);
            for (const auto& act : pm->actions) {
                commands_arr.push_back(pm->name + " " + act);
            }
        }

        return nlohmann::json({{"plugins", plugins_arr}, {"commands", commands_arr}}).dump();
    }

    // Get list of all agent IDs.
    std::vector<std::string> all_ids() const {
        std::lock_guard lock(mu_);
        std::vector<std::string> ids;
        ids.reserve(agents_.size());
        for (const auto& id : agents_ | std::views::keys) {
            ids.push_back(id);
        }
        return ids;
    }

    // Look up the agent_id that was registered for a given Subscribe call.
    // The Subscribe RPC needs to know which agent_id it's serving.
    std::string find_agent_by_stream(
        grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) const {
        std::lock_guard lock(mu_);
        for (const auto& [id, s] : agents_) {
            std::lock_guard slock(s->stream_mu);
            if (s->stream == stream)
                return id;
        }
        return {};
    }

    std::size_t agent_count() const {
        std::lock_guard lock(mu_);
        return agents_.size();
    }

    // Map a session_id to an agent_id (called when Subscribe completes handshake).
    void map_session(const std::string& session_id, const std::string& agent_id) {
        std::lock_guard lock(mu_);
        session_to_agent_[session_id] = agent_id;
    }

    // Look up agent session by session_id (for heartbeat validation).
    std::shared_ptr<AgentSession> find_by_session(std::string_view session_id) const {
        std::lock_guard lock(mu_);
        auto sit = session_to_agent_.find(std::string(session_id));
        if (sit == session_to_agent_.end())
            return nullptr;
        auto ait = agents_.find(sit->second);
        return ait != agents_.end() ? ait->second : nullptr;
    }

    // Get a session by agent_id (for scope evaluation).
    std::shared_ptr<AgentSession> get_session(const std::string& agent_id) const {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        return it != agents_.end() ? it->second : nullptr;
    }

    // Evaluate a scope expression against all agents, return matching agent IDs.
    std::vector<std::string> evaluate_scope(const yuzu::scope::Expression& expr,
                                            const TagStore* tag_store) const {
        std::vector<std::string> matched;
        std::lock_guard lock(mu_);
        for (const auto& [id, session] : agents_) {
            auto resolver = [&](std::string_view attr) -> std::string {
                auto key = std::string(attr);
                if (key == "ostype")
                    return session->os;
                if (key == "hostname")
                    return session->hostname;
                if (key == "arch")
                    return session->arch;
                if (key == "agent_version")
                    return session->agent_version;
                // tag:X lookups
                if (key.starts_with("tag:")) {
                    auto tag_key = key.substr(4);
                    // First check in-memory scopable_tags
                    auto it = session->scopable_tags.find(tag_key);
                    if (it != session->scopable_tags.end())
                        return it->second;
                    // Then check persistent TagStore
                    if (tag_store)
                        return tag_store->get_tag(id, tag_key);
                }
                return {};
            };
            if (yuzu::scope::evaluate(expr, resolver)) {
                matched.push_back(id);
            }
        }
        return matched;
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<AgentSession>> agents_;
    std::unordered_map<std::string, std::string> session_to_agent_;
    EventBus& bus_;
    yuzu::MetricsRegistry& metrics_;
};

// -- SSE sink state (per-connection, shared with content provider) -------------

struct SseSinkState {
    std::mutex mu;
    std::condition_variable cv;
    std::deque<SseEvent> queue;
    std::atomic<bool> closed = false;
    std::size_t sub_id = 0;
};

// -- SSE content provider callback --------------------------------------------

bool sse_content_provider(const std::shared_ptr<SseSinkState>& state, size_t /*offset*/,
                          httplib::DataSink& sink) {
    std::unique_lock<std::mutex> lk(state->mu);
    state->cv.wait_for(lk, std::chrono::seconds(15),
                       [&state] { return !state->queue.empty() || state->closed.load(); });

    if (state->closed.load()) {
        return false;
    }

    while (!state->queue.empty()) {
        auto& ev = state->queue.front();
        std::string sse = "event: " + ev.event_type + "\ndata: " + ev.data + "\n\n";
        if (!sink.write(sse.data(), sse.size())) {
            return false;
        }
        state->queue.pop_front();
    }

    const char* keepalive = ": keepalive\n\n";
    sink.write(keepalive, std::strlen(keepalive));
    return true;
}

void sse_resource_release(const std::shared_ptr<SseSinkState>& state, EventBus& bus,
                          bool /*success*/) {
    state->closed.store(true);
    state->cv.notify_all();
    bus.unsubscribe(state->sub_id);
}

// -- AgentHealthStore ---------------------------------------------------------
// Aggregates per-agent heartbeat status_tags into fleet-wide Prometheus metrics.

struct AgentHealthSnapshot {
    std::string agent_id;
    std::unordered_map<std::string, std::string> status_tags;
    std::chrono::steady_clock::time_point last_seen;
};

class AgentHealthStore {
public:
    void upsert(const std::string& agent_id,
                const google::protobuf::Map<std::string, std::string>& tags) {
        std::lock_guard lock(mu_);
        auto& snap = snapshots_[agent_id];
        snap.agent_id = agent_id;
        snap.status_tags.clear();
        for (const auto& [k, v] : tags) {
            snap.status_tags[k] = v;
        }
        snap.last_seen = std::chrono::steady_clock::now();
    }

    void remove(const std::string& agent_id) {
        std::lock_guard lock(mu_);
        snapshots_.erase(agent_id);
    }

    void recompute_metrics(yuzu::MetricsRegistry& metrics, std::chrono::seconds staleness) {
        std::lock_guard lock(mu_);
        auto now = std::chrono::steady_clock::now();

        // Prune stale entries
        std::erase_if(snapshots_,
                      [&](const auto& pair) { return (now - pair.second.last_seen) > staleness; });

        // Clear labeled gauge families before rebuilding
        metrics.clear_gauge_family("yuzu_fleet_agents_by_os");
        metrics.clear_gauge_family("yuzu_fleet_agents_by_arch");
        metrics.clear_gauge_family("yuzu_fleet_agents_by_version");

        // Aggregate
        std::unordered_map<std::string, int> os_counts;
        std::unordered_map<std::string, int> arch_counts;
        std::unordered_map<std::string, int> version_counts;
        double total_commands = 0.0;
        int healthy_count = 0;

        for (const auto& [id, snap] : snapshots_) {
            ++healthy_count;

            auto get = [&](const std::string& key) -> std::string {
                auto it = snap.status_tags.find(key);
                return it != snap.status_tags.end() ? it->second : "";
            };

            auto os_val = get("yuzu.os");
            if (!os_val.empty())
                os_counts[os_val]++;

            auto arch_val = get("yuzu.arch");
            if (!arch_val.empty())
                arch_counts[arch_val]++;

            auto ver_val = get("yuzu.agent_version");
            if (!ver_val.empty())
                version_counts[ver_val]++;

            auto cmd_val = get("yuzu.commands_executed");
            if (!cmd_val.empty()) {
                try {
                    total_commands += std::stod(cmd_val);
                } catch (...) {}
            }
        }

        metrics.gauge("yuzu_fleet_agents_healthy").set(static_cast<double>(healthy_count));

        for (const auto& [os, count] : os_counts) {
            metrics.gauge("yuzu_fleet_agents_by_os", {{"os", os}}).set(static_cast<double>(count));
        }
        for (const auto& [arch, count] : arch_counts) {
            metrics.gauge("yuzu_fleet_agents_by_arch", {{"arch", arch}})
                .set(static_cast<double>(count));
        }
        for (const auto& [ver, count] : version_counts) {
            metrics.gauge("yuzu_fleet_agents_by_version", {{"version", ver}})
                .set(static_cast<double>(count));
        }
        metrics.gauge("yuzu_fleet_commands_executed_total").set(total_commands);
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, AgentHealthSnapshot> snapshots_;
};

// -- AgentServiceImpl ---------------------------------------------------------

class AgentServiceImpl : public pb::AgentService::Service {
public:
    AgentServiceImpl(AgentRegistry& registry, EventBus& bus, bool require_client_identity,
                     auth::AuthManager& auth_mgr, auth::AutoApproveEngine& auto_approve,
                     yuzu::MetricsRegistry& metrics, bool gateway_mode = false,
                     UpdateRegistry* update_registry = nullptr)
        : registry_(registry), bus_(bus), auth_mgr_(auth_mgr), auto_approve_(auto_approve),
          metrics_(metrics), require_client_identity_(require_client_identity),
          gateway_mode_(gateway_mode), update_registry_(update_registry) {}

    void set_update_registry(UpdateRegistry* reg) { update_registry_ = reg; }
    void set_response_store(ResponseStore* store) { response_store_ = store; }
    void set_tag_store(TagStore* store) { tag_store_ = store; }
    void set_analytics_store(AnalyticsEventStore* store) { analytics_store_ = store; }
    void set_health_store(AgentHealthStore* store) { health_store_ = store; }
    void set_mgmt_group_store(ManagementGroupStore* store) { mgmt_group_store_ = store; }

    grpc::Status Register(grpc::ServerContext* context, const pb::RegisterRequest* request,
                          pb::RegisterResponse* response) override {
        metrics_
            .counter("yuzu_grpc_requests_total", {{"method", "Register"}, {"status", "received"}})
            .increment();
        const auto& info = request->info();

        if (require_client_identity_) {
            if (!context || !peer_identity_matches_agent_id(*context, info.agent_id())) {
                spdlog::warn("mTLS identity mismatch: claimed agent_id={}", info.agent_id());
                return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                                    "agent_id must match client certificate identity (CN/SAN)");
            }
        }

        // ── Tiered enrollment ────────────────────────────────────────────
        //
        //  Tier 2: Pre-shared enrollment token → auto-enroll
        //  Tier 1: No token → check pending queue → pending/approved/denied
        //

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
            // Remove from pending queue if it was there
            auth_mgr_.remove_pending_agent(info.agent_id());
        } else {
            // Tier 1.5: Auto-approve policies — check before pending queue
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

            // TODO: Extract CA fingerprint from peer TLS cert chain
            // approval_ctx.ca_fingerprint_sha256 = ...

            auto matched_rule = auto_approve_.evaluate(approval_ctx);
            if (!matched_rule.empty()) {
                spdlog::info("Agent {} auto-approved by policy: {}", info.agent_id(), matched_rule);
                auth_mgr_.remove_pending_agent(info.agent_id());
                // Fall through to normal registration
            } else {
                // Tier 1: No token, no policy match — check the pending queue
                auto pending_status = auth_mgr_.get_pending_status(info.agent_id());

                if (!pending_status) {
                    // First time seeing this agent — add to pending queue
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

        // ── Agent is enrolled — proceed with registration ────────────────

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
                {"enrollment_method", enrollment_token.empty() ? "approval" : "token"}};
            nlohmann::json plugins_list = nlohmann::json::array();
            for (const auto& p : info.plugins()) {
                plugins_list.push_back(p.name());
            }
            ae.payload = {{"plugins", plugins_list}};
            analytics_store_->emit(std::move(ae));
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

    grpc::Status Heartbeat(grpc::ServerContext* /*context*/, const pb::HeartbeatRequest* request,
                           pb::HeartbeatResponse* response) override {
        metrics_
            .counter("yuzu_grpc_requests_total", {{"method", "Heartbeat"}, {"status", "received"}})
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

        // Store health snapshot
        if (health_store_) {
            health_store_->upsert(agent_id, request->status_tags());
        }
        metrics_.counter("yuzu_heartbeats_received_total", {{"via", "direct"}}).increment();

        response->set_acknowledged(true);
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();
        response->mutable_server_time()->set_millis_epoch(now_ms);

        spdlog::debug("Heartbeat from agent={} (session={})", agent_id, session_id);
        return grpc::Status::OK;
    }

    grpc::Status
    Subscribe(grpc::ServerContext* context,
              grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) override {
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
                    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                                        "peer identity mismatch");
                }
            }

            agent_id = it->second.agent_id;
            pending_by_session_id_.erase(it);
        }

        spdlog::info("Agent subscribe stream opened for {}", agent_id);
        registry_.set_stream(agent_id, stream);
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

        // Read loop — process responses from the agent
        pb::CommandResponse resp;
        while (stream->Read(&resp)) {
            if (resp.status() == pb::CommandResponse::RUNNING) {
                // Intercept __timing__ metadata
                if (resp.output().starts_with("__timing__|")) {
                    auto payload = resp.output().substr(11);
                    bus_.publish("timing", resp.command_id() + "|" + payload + "|agent_total");
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
                            bus_.publish("timing", resp.command_id() + "|first_data_ms=" +
                                                       std::to_string(elapsed) + "|first_data");
                        }
                    }
                }

                // Determine the plugin from command_id prefix (format: plugin-timestamp)
                std::string plugin = extract_plugin(resp.command_id());

                // Publish as generic output event: agent_id|plugin|data
                bus_.publish("output", agent_id + "|" + plugin + "|" + resp.output());

                // Store streaming response
                if (response_store_) {
                    StoredResponse sr;
                    sr.instruction_id = resp.command_id();
                    sr.agent_id = agent_id;
                    sr.status = static_cast<int>(resp.status());
                    sr.output = resp.output();
                    response_store_->store(sr);
                }

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
                    StoredResponse sr;
                    sr.instruction_id = resp.command_id();
                    sr.agent_id = agent_id;
                    sr.status = static_cast<int>(resp.status());
                    sr.output = resp.output();
                    if (resp.has_error()) {
                        sr.error_detail = resp.error().message();
                    }
                    response_store_->store(sr);
                }

                std::string status_str =
                    (resp.status() == pb::CommandResponse::SUCCESS) ? "done" : "error";
                metrics_.counter("yuzu_commands_completed_total", {{"status", status_str}})
                    .increment();
                bus_.publish("command-status", resp.command_id() + "|" + status_str);

                if (analytics_store_) {
                    AnalyticsEvent ae;
                    ae.event_type = "command.completed";
                    ae.agent_id = agent_id;
                    ae.plugin = extract_plugin(resp.command_id());
                    ae.correlation_id = resp.command_id();
                    ae.severity = (resp.status() == pb::CommandResponse::SUCCESS)
                                      ? Severity::kInfo
                                      : Severity::kError;
                    ae.payload = {{"status", status_str}, {"exit_code", resp.exit_code()}};
                    if (resp.has_error()) {
                        ae.payload["error_message"] = resp.error().message();
                    }
                    analytics_store_->emit(std::move(ae));
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
                        bus_.publish("timing", resp.command_id() + "|total_ms=" +
                                                   std::to_string(total_ms) + "|complete");
                        cmd_send_times_.erase(it);
                    }
                    cmd_first_seen_.erase(resp.command_id());
                }
            }
        }

        // Agent disconnected
        registry_.clear_stream(agent_id);
        registry_.remove_agent(agent_id);
        spdlog::info("Agent subscribe stream closed for {}", agent_id);

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

    // Record send time for latency measurement.
    void record_send_time(const std::string& command_id) {
        std::lock_guard lock(cmd_times_mu_);
        cmd_send_times_[command_id] = std::chrono::steady_clock::now();
    }

private:
    struct PendingRegistration {
        std::string agent_id;
        std::string register_peer;
        std::vector<std::string> peer_identities;
        std::chrono::steady_clock::time_point created_at;
    };

    static std::vector<std::string> extract_peer_identities(const grpc::ServerContext& context) {
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

    static bool peer_identity_matches_agent_id(const grpc::ServerContext& context,
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

    static std::string client_metadata_value(const grpc::ServerContext& context,
                                             std::string_view key) {
        const auto& md = context.client_metadata();
        auto it = md.find(std::string(key));
        if (it == md.end())
            return {};
        return std::string(it->second.data(), it->second.length());
    }

    static bool has_identity_overlap(const std::vector<std::string>& lhs,
                                     const std::vector<std::string>& rhs) {
        for (const auto& left : lhs) {
            for (const auto& right : rhs) {
                if (left == right)
                    return true;
            }
        }
        return false;
    }

    void prune_expired_pending_locked() {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = pending_by_session_id_.begin(); it != pending_by_session_id_.end();) {
            if (now - it->second.created_at > kPendingRegistrationTtl) {
                it = pending_by_session_id_.erase(it);
            } else {
                ++it;
            }
        }
    }

    static std::string extract_plugin(const std::string& command_id) {
        // command_id format: "plugin-timestamp" e.g. "chargen-12345" or "netstat-12345"
        auto dash = command_id.find('-');
        if (dash != std::string::npos) {
            return command_id.substr(0, dash);
        }
        return command_id;
    }

    // ── OTA Update RPCs ─────────────────────────────────────────────────────

    grpc::Status CheckForUpdate(grpc::ServerContext* /*context*/,
                                const pb::CheckForUpdateRequest* request,
                                pb::CheckForUpdateResponse* response) override {
        metrics_
            .counter("yuzu_grpc_requests_total",
                     {{"method", "CheckForUpdate"}, {"status", "received"}})
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

    grpc::Status DownloadUpdate(grpc::ServerContext* /*context*/,
                                const pb::DownloadUpdateRequest* request,
                                grpc::ServerWriter<pb::DownloadUpdateChunk>* writer) override {
        metrics_
            .counter("yuzu_grpc_requests_total",
                     {{"method", "DownloadUpdate"}, {"status", "received"}})
            .increment();

        if (!update_registry_) {
            return grpc::Status(grpc::StatusCode::UNAVAILABLE, "OTA not configured");
        }

        auto pkg =
            update_registry_->latest_for(request->platform().os(), request->platform().arch());
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

    AgentRegistry& registry_;
    EventBus& bus_;
    auth::AuthManager& auth_mgr_;
    auth::AutoApproveEngine& auto_approve_;
    yuzu::MetricsRegistry& metrics_;

    static constexpr std::string_view kSessionMetadataKey = "x-yuzu-session-id";
    static constexpr auto kPendingRegistrationTtl = std::chrono::seconds(60);

    // Pending Register calls waiting for the corresponding Subscribe.
    std::mutex pending_mu_;
    std::unordered_map<std::string, PendingRegistration> pending_by_session_id_;

    // Command timing instrumentation
    std::mutex cmd_times_mu_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> cmd_send_times_;
    std::unordered_set<std::string> cmd_first_seen_;
    bool require_client_identity_{false};
    bool gateway_mode_{false};
    UpdateRegistry* update_registry_{nullptr};
    ResponseStore* response_store_{nullptr};
    TagStore* tag_store_{nullptr};
    AnalyticsEventStore* analytics_store_{nullptr};
    AgentHealthStore* health_store_{nullptr};
    ManagementGroupStore* mgmt_group_store_{nullptr};
};

// -- ManagementServiceImpl ----------------------------------------------------

class ManagementServiceImpl : public ::yuzu::server::v1::ManagementService::Service {
public:
    // Placeholder.
};

// -- GatewayUpstreamServiceImpl -----------------------------------------------

class GatewayUpstreamServiceImpl : public gw::GatewayUpstream::Service {
public:
    GatewayUpstreamServiceImpl(AgentRegistry& registry, EventBus& bus, auth::AuthManager& auth_mgr,
                               auth::AutoApproveEngine& auto_approve,
                               yuzu::MetricsRegistry* metrics = nullptr,
                               AgentHealthStore* health_store = nullptr)
        : registry_(registry), bus_(bus), auth_mgr_(auth_mgr), auto_approve_(auto_approve),
          metrics_(metrics), health_store_(health_store) {}

    void set_mgmt_group_store(ManagementGroupStore* store) { mgmt_group_store_ = store; }

    // -- ProxyRegister --------------------------------------------------------
    // Gateway forwards an agent's RegisterRequest.  We run the same enrollment
    // logic as AgentServiceImpl::Register but skip peer-identity checks (the
    // gateway is a trusted internal service).

    grpc::Status ProxyRegister(grpc::ServerContext* /*context*/, const pb::RegisterRequest* request,
                               pb::RegisterResponse* response) override {
        const auto& info = request->info();

        // ── Tiered enrollment (same logic as AgentServiceImpl::Register) ─────
        const auto& enrollment_token = request->enrollment_token();

        if (!enrollment_token.empty()) {
            if (!auth_mgr_.validate_enrollment_token(enrollment_token)) {
                spdlog::warn("[gateway] Agent {} presented invalid enrollment token",
                             info.agent_id());
                response->set_accepted(false);
                response->set_reject_reason("invalid, expired, or exhausted enrollment token");
                response->set_enrollment_status("denied");
                return grpc::Status::OK;
            }
            spdlog::info("[gateway] Agent {} auto-enrolled via enrollment token", info.agent_id());
            auth_mgr_.remove_pending_agent(info.agent_id());
        } else {
            // Auto-approve policies (no peer IP available from gateway yet)
            auth::ApprovalContext approval_ctx;
            approval_ctx.hostname = info.hostname();
            approval_ctx.attestation_provider = request->attestation_provider();

            auto matched_rule = auto_approve_.evaluate(approval_ctx);
            if (!matched_rule.empty()) {
                spdlog::info("[gateway] Agent {} auto-approved by policy: {}", info.agent_id(),
                             matched_rule);
                auth_mgr_.remove_pending_agent(info.agent_id());
            } else {
                // Tier 1: pending queue
                auto pending_status = auth_mgr_.get_pending_status(info.agent_id());

                if (!pending_status) {
                    auth_mgr_.add_pending_agent(info.agent_id(), info.hostname(),
                                                info.platform().os(), info.platform().arch(),
                                                info.agent_version());

                    response->set_accepted(false);
                    response->set_reject_reason("awaiting admin approval");
                    response->set_enrollment_status("pending");
                    bus_.publish("pending-agent", info.agent_id());
                    spdlog::info("[gateway] Agent {} placed in pending queue", info.agent_id());
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
                    return grpc::Status::OK;
                case auth::PendingStatus::approved:
                    spdlog::info("[gateway] Agent {} enrolled (admin-approved)", info.agent_id());
                    break;
                }
            }
        }

        // ── Enrolled — register the agent ────────────────────────────────────
        registry_.register_agent(info);
        // Auto-add to root management group
        if (mgmt_group_store_ && mgmt_group_store_->is_open())
            mgmt_group_store_->add_member(ManagementGroupStore::kRootGroupId, info.agent_id());

        auto session_id =
            "gw-session-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(16));
        response->set_session_id(session_id);
        response->set_accepted(true);
        response->set_enrollment_status("enrolled");

        {
            std::lock_guard lock(sessions_mu_);
            gateway_sessions_[session_id] = info.agent_id();
        }

        spdlog::info("[gateway] ProxyRegister succeeded: agent={}, session={}", info.agent_id(),
                     session_id);
        return grpc::Status::OK;
    }

    // -- BatchHeartbeat -------------------------------------------------------

    grpc::Status BatchHeartbeat(grpc::ServerContext* /*context*/,
                                const gw::BatchHeartbeatRequest* request,
                                gw::BatchHeartbeatResponse* response) override {
        int acked = 0;
        for (const auto& hb : request->heartbeats()) {
            // Validate that the session is known
            std::string agent_id;
            {
                std::lock_guard lock(sessions_mu_);
                auto it = gateway_sessions_.find(hb.session_id());
                if (it != gateway_sessions_.end()) {
                    agent_id = it->second;
                }
            }
            if (agent_id.empty()) {
                spdlog::debug("[gateway] BatchHeartbeat: unknown session {}", hb.session_id());
                continue;
            }
            // Store agent health from piggybacked status_tags
            if (health_store_) {
                health_store_->upsert(agent_id, hb.status_tags());
            }
            if (metrics_) {
                metrics_->counter("yuzu_heartbeats_received_total", {{"via", "gateway"}})
                    .increment();
            }
            ++acked;
        }

        response->set_acknowledged_count(acked);
        spdlog::debug("[gateway] BatchHeartbeat from node '{}': {}/{} acked",
                      request->gateway_node(), acked, request->heartbeats_size());
        return grpc::Status::OK;
    }

    // -- ProxyInventory -------------------------------------------------------

    grpc::Status ProxyInventory(grpc::ServerContext* /*context*/,
                                const pb::InventoryReport* request,
                                pb::InventoryAck* response) override {
        std::string agent_id;
        {
            std::lock_guard lock(sessions_mu_);
            auto it = gateway_sessions_.find(request->session_id());
            if (it != gateway_sessions_.end()) {
                agent_id = it->second;
            }
        }
        if (agent_id.empty()) {
            spdlog::warn("[gateway] ProxyInventory: unknown session {}", request->session_id());
            response->set_received(false);
            return grpc::Status::OK;
        }

        // TODO: Persist inventory data once storage layer is implemented.
        spdlog::info("[gateway] ProxyInventory received for agent={}, plugins={}", agent_id,
                     request->plugin_data_size());
        response->set_received(true);
        return grpc::Status::OK;
    }

    // -- NotifyStreamStatus ---------------------------------------------------

    grpc::Status NotifyStreamStatus(grpc::ServerContext* /*context*/,
                                    const gw::StreamStatusNotification* request,
                                    gw::StreamStatusAck* response) override {
        const auto& agent_id = request->agent_id();
        const auto& session_id = request->session_id();

        // Verify session
        {
            std::lock_guard lock(sessions_mu_);
            auto it = gateway_sessions_.find(session_id);
            if (it == gateway_sessions_.end() || it->second != agent_id) {
                spdlog::warn("[gateway] NotifyStreamStatus: unknown session {} for agent {}",
                             session_id, agent_id);
                response->set_acknowledged(false);
                return grpc::Status::OK;
            }
        }

        switch (request->event()) {
        case gw::StreamStatusNotification::CONNECTED:
            // The gateway now owns the Subscribe stream for this agent.
            // We don't have a local stream pointer, so we mark stream as null
            // but keep the agent registered (it was registered in ProxyRegister).
            spdlog::info("[gateway] Agent {} stream CONNECTED at gateway node '{}'", agent_id,
                         request->gateway_node());
            break;

        case gw::StreamStatusNotification::DISCONNECTED:
            registry_.clear_stream(agent_id);
            registry_.remove_agent(agent_id);
            {
                std::lock_guard lock(sessions_mu_);
                gateway_sessions_.erase(session_id);
            }
            spdlog::info("[gateway] Agent {} stream DISCONNECTED at gateway node '{}'", agent_id,
                         request->gateway_node());
            break;

        default:
            spdlog::warn("[gateway] NotifyStreamStatus: unknown event {} for agent {}",
                         static_cast<int>(request->event()), agent_id);
            response->set_acknowledged(false);
            return grpc::Status::OK;
        }

        response->set_acknowledged(true);
        return grpc::Status::OK;
    }

private:
    AgentRegistry& registry_;
    EventBus& bus_;
    auth::AuthManager& auth_mgr_;
    auth::AutoApproveEngine& auto_approve_;
    yuzu::MetricsRegistry* metrics_{nullptr};
    AgentHealthStore* health_store_{nullptr};
    ManagementGroupStore* mgmt_group_store_{nullptr};

    // Map of gateway session_id → agent_id for validation.
    std::mutex sessions_mu_;
    std::unordered_map<std::string, std::string> gateway_sessions_;
};

// -- File-reading helper ------------------------------------------------------

std::string read_file_contents(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f)
        return {};
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

} // namespace detail

// -- ServerImpl ---------------------------------------------------------------

class ServerImpl final : public Server {
public:
    explicit ServerImpl(Config cfg, auth::AuthManager& auth_mgr)
        : cfg_(std::move(cfg)), auth_mgr_(auth_mgr), auto_approve_(), metrics_(), event_bus_(),
          registry_(event_bus_, metrics_),
          agent_service_(registry_, event_bus_, cfg_.tls_enabled && !cfg_.tls_ca_cert.empty(),
                         auth_mgr, auto_approve_, metrics_, cfg_.gateway_mode) {
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

        // Wire health store into agent service
        agent_service_.set_health_store(&health_store_);

        // Create gateway upstream service if configured
        if (!cfg_.gateway_upstream_address.empty()) {
            gateway_service_ = std::make_unique<detail::GatewayUpstreamServiceImpl>(
                registry_, event_bus_, auth_mgr, auto_approve_, &metrics_, &health_store_);
        }

        // Load auto-approve policies
        auto approve_path = cfg_.auth_config_path.parent_path() / "auto-approve.cfg";
        auto_approve_.load(approve_path);

        // Initialize OIDC provider if configured
        if (!cfg_.oidc_issuer.empty() && !cfg_.oidc_client_id.empty()) {
            oidc::OidcConfig oidc_cfg;
            oidc_cfg.issuer = cfg_.oidc_issuer;
            oidc_cfg.client_id = cfg_.oidc_client_id;
            oidc_cfg.client_secret = cfg_.oidc_client_secret;
            oidc_cfg.redirect_uri = cfg_.oidc_redirect_uri;
            oidc_cfg.admin_group_id = cfg_.oidc_admin_group;
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

        // Setup file logger
        auto log_path = detail::server_log_path();
        auto parent = log_path.parent_path();
        if (!parent.empty()) {
            std::error_code ec;
            std::filesystem::create_directories(parent, ec);
            if (ec) {
                spdlog::warn("Could not create log directory {}: {}", parent.string(),
                             ec.message());
            }
        }
        try {
            file_logger_ = spdlog::basic_logger_mt("server_file", log_path.string());
            file_logger_->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [server] %v");
            file_logger_->flush_on(spdlog::level::info);
            spdlog::info("Log file: {}", log_path.string());
        } catch (const spdlog::spdlog_ex& ex) {
            spdlog::error("Failed to create file logger: {}", ex.what());
        }

        // Initialize NVD CVE database
        auto nvd_path = cfg_.auth_config_path.parent_path() / "nvd_cves.db";
        nvd_db_ = std::make_shared<NvdDatabase>(nvd_path);

        if (cfg_.nvd_sync_enabled && nvd_db_->is_open()) {
            nvd_sync_ = std::make_unique<NvdSyncManager>(nvd_db_, cfg_.nvd_api_key, cfg_.nvd_proxy,
                                                         cfg_.nvd_sync_interval);
            nvd_sync_->start();
        }

        // Initialize OTA update registry
        if (cfg_.ota_enabled) {
            auto update_db_path = cfg_.auth_config_path.parent_path() / "update_packages.db";
            auto update_dir = cfg_.update_dir.empty()
                                  ? cfg_.auth_config_path.parent_path() / "agent-updates"
                                  : cfg_.update_dir;
            std::error_code ec;
            std::filesystem::create_directories(update_dir, ec);
            update_registry_ = std::make_unique<UpdateRegistry>(update_db_path, update_dir);
            agent_service_.set_update_registry(update_registry_.get());
        }

        // Wire up cross-references for AgentServiceImpl
        // (done after stores are created below)

        // Initialize response store
        {
            auto resp_db = cfg_.auth_config_path.parent_path() / "responses.db";
            response_store_ =
                std::make_unique<ResponseStore>(resp_db, cfg_.response_retention_days);
            if (response_store_->is_open()) {
                response_store_->start_cleanup();
            }
        }

        // Initialize audit store
        {
            auto audit_db = cfg_.auth_config_path.parent_path() / "audit.db";
            audit_store_ = std::make_unique<AuditStore>(audit_db, cfg_.audit_retention_days);
            if (audit_store_->is_open()) {
                audit_store_->start_cleanup();
            }
        }

        // Initialize tag store
        {
            auto tag_db = cfg_.auth_config_path.parent_path() / "tags.db";
            tag_store_ = std::make_unique<TagStore>(tag_db);
        }

        // Initialize analytics event store
        if (cfg_.analytics_enabled) {
            auto analytics_db = cfg_.auth_config_path.parent_path() / "analytics.db";
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

        // Initialize instruction store (Phase 2)
        {
            auto instr_db = cfg_.auth_config_path.parent_path() / "instructions.db";
            instruction_store_ = std::make_unique<InstructionStore>(instr_db);
            if (instruction_store_ && instruction_store_->is_open()) {
                // ExecutionTracker, ApprovalManager, ScheduleEngine share the same DB
                // They use the raw db pointer from InstructionStore's internal handle
                // Since they need the same db, we open a second connection for them
                sqlite3* shared_db = nullptr;
                int rc = sqlite3_open(instr_db.string().c_str(), &shared_db);
                if (rc == SQLITE_OK) {
                    sqlite3_exec(shared_db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
                    sqlite3_exec(shared_db, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
                    shared_instr_db_ = shared_db;

                    execution_tracker_ = std::make_unique<ExecutionTracker>(shared_db);
                    execution_tracker_->create_tables();

                    approval_manager_ = std::make_unique<ApprovalManager>(shared_db);
                    approval_manager_->create_tables();

                    schedule_engine_ = std::make_unique<ScheduleEngine>(shared_db);
                    schedule_engine_->create_tables();
                }
            }
        }

        // Initialize Phase 3: Security & RBAC stores
        {
            auto rbac_db = cfg_.auth_config_path.parent_path() / "rbac.db";
            rbac_store_ = std::make_unique<RbacStore>(rbac_db);
        }
        {
            auto mgmt_db = cfg_.auth_config_path.parent_path() / "management-groups.db";
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
            auto token_db = cfg_.auth_config_path.parent_path() / "api-tokens.db";
            api_token_store_ = std::make_unique<ApiTokenStore>(token_db);
        }
        {
            auto quar_db = cfg_.auth_config_path.parent_path() / "quarantine.db";
            quarantine_store_ = std::make_unique<QuarantineStore>(quar_db);
        }

        // Phase 5: Policy Engine
        {
            auto policy_db = cfg_.auth_config_path.parent_path() / "policies.db";
            policy_store_ = std::make_unique<PolicyStore>(policy_db);
            if (policy_store_ && policy_store_->is_open()) {
                spdlog::info("PolicyStore initialized at {}", policy_db.string());
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
                auto mgmt_tls =
                    build_tls_credentials(cfg_.mgmt_tls_server_cert, cfg_.mgmt_tls_server_key,
                                          cfg_.mgmt_tls_ca_cert, true, "management listener");
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

        start_web_server();

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
            }
            spdlog::info("Fleet health recomputation thread stopped");
        });

        agent_server_->Wait();
    }

    void stop() noexcept override {
        spdlog::info("Shutting down server...");
        stop_requested_.store(true, std::memory_order_release);

        // Join the fleet health recomputation thread
        if (health_recompute_thread_.joinable()) {
            health_recompute_thread_.join();
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

        // Release Phase 2 components before closing shared DB
        execution_tracker_.reset();
        approval_manager_.reset();
        schedule_engine_.reset();
        if (shared_instr_db_) {
            sqlite3_close(shared_instr_db_);
            shared_instr_db_ = nullptr;
        }

        if (agent_server_)
            agent_server_->Shutdown();
        if (mgmt_server_)
            mgmt_server_->Shutdown();
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
                spdlog::error("{} TLS requires --ca-cert (or enable --allow-one-way-tls)",
                              listener_name);
                return nullptr;
            }
            spdlog::warn("{} TLS running without client certificate verification", listener_name);
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
    // Returns highlighted HTML from raw YAML source.  Each line is wrapped in
    // <div class="yl"><span class="ln">N</span>content</div>.

    static std::string highlight_yaml_value(const std::string& val) {
        if (val.empty())
            return {};
        // Trim leading space for classification but keep original for output
        auto trimmed = val;
        auto sp = trimmed.find_first_not_of(' ');
        if (sp == std::string::npos)
            return html_escape(val);
        trimmed = trimmed.substr(sp);

        // Booleans
        if (trimmed == "true" || trimmed == "false" || trimmed == "True" || trimmed == "False")
            return "<span class=\"yb\">" + html_escape(val) + "</span>";
        // Numbers
        bool is_number = !trimmed.empty();
        for (char c : trimmed) {
            if (c != '-' && c != '.' && (c < '0' || c > '9')) {
                is_number = false;
                break;
            }
        }
        if (is_number && !trimmed.empty())
            return "<span class=\"yn\">" + html_escape(val) + "</span>";
        // String value (quoted or bare)
        return "<span class=\"yv\">" + html_escape(val) + "</span>";
    }

    static std::string highlight_yaml_kv(const std::string& line) {
        // Match key: value — key is [\w.\-]+
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
        auto rest = line.substr(i + 1); // after ':'

        // Special schema keywords
        bool is_schema = (key == "apiVersion" || key == "kind");
        std::string key_cls = is_schema ? "ya" : "yk";

        return html_escape(indent) + "<span class=\"" + key_cls + "\">" +
               html_escape(key) + "</span>:" + highlight_yaml_value(rest);
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

            result += "<div class=\"yl\"><span class=\"ln\">" +
                      std::to_string(line_num++) + "</span>";

            // Classify line
            auto trimmed_start = line.find_first_not_of(' ');
            if (trimmed_start == std::string::npos) {
                // Blank line
                result += "&nbsp;";
            } else if (line[trimmed_start] == '#') {
                // Comment
                result += "<span class=\"yc\">" + html_escape(line) + "</span>";
            } else if (line == "---" || line == "...") {
                // Document separator
                result += "<span class=\"yd\">" + html_escape(line) + "</span>";
            } else if (line[trimmed_start] == '-' && trimmed_start + 1 < line.size() &&
                       line[trimmed_start + 1] == ' ') {
                // List marker
                auto indent = line.substr(0, trimmed_start);
                auto after_dash = line.substr(trimmed_start + 2);
                result += html_escape(indent) + "<span class=\"yd\">-</span> ";
                // Check if remainder is key:value
                if (after_dash.find(':') != std::string::npos)
                    result += highlight_yaml_kv(after_dash);
                else
                    result += highlight_yaml_value(after_dash);
            } else if (line.find(':') != std::string::npos) {
                // Key: value pair
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

    static std::string extract_session_cookie(const httplib::Request& req) {
        auto cookie = req.get_header_value("Cookie");
        // Find yuzu_session=<token>
        const std::string prefix = "yuzu_session=";
        auto pos = cookie.find(prefix);
        if (pos == std::string::npos)
            return {};
        pos += prefix.size();
        auto end = cookie.find(';', pos);
        return cookie.substr(pos, end == std::string::npos ? end : end - pos);
    }

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

    /// Build a session from a validated API token, resolving the creator's actual role.
    auth::Session synthesize_token_session(const ApiToken& api_token) {
        auth::Session synth;
        synth.username = api_token.principal_id;
        synth.auth_source = "api_token";
        synth.token_scope_service = api_token.scope_service;

        // Resolve the creator's actual legacy role (not unconditional admin)
        auto legacy_role = auth_mgr_.get_user_role(api_token.principal_id);
        synth.role = legacy_role.value_or(auth::Role::user);

        return synth;
    }

    std::optional<auth::Session> require_auth(const httplib::Request& req, httplib::Response& res) {
        // 1. Try session cookie (existing browser auth)
        auto token = extract_session_cookie(req);
        auto session = auth_mgr_.validate_session(token);
        if (session)
            return session;

        // 2. Try Authorization: Bearer <token> (API token auth)
        auto auth_header = req.get_header_value("Authorization");
        if (auth_header.size() > 7 && auth_header.substr(0, 7) == "Bearer ") {
            auto raw = auth_header.substr(7);
            if (api_token_store_) {
                auto api_token = api_token_store_->validate_token(raw);
                if (api_token)
                    return synthesize_token_session(*api_token);
            }
        }

        // 3. Try X-Yuzu-Token header (alternative API token header)
        auto custom_header = req.get_header_value("X-Yuzu-Token");
        if (!custom_header.empty() && api_token_store_) {
            auto api_token = api_token_store_->validate_token(custom_header);
            if (api_token)
                return synthesize_token_session(*api_token);
        }

        res.status = 401;
        res.set_content(R"({"error":"unauthorized"})", "application/json");
        return std::nullopt;
    }

    bool require_admin(const httplib::Request& req, httplib::Response& res) {
        auto session = require_auth(req, res);
        if (!session)
            return false;
        if (session->role != auth::Role::admin) {
            res.status = 403;
            res.set_content(R"({"error":"admin role required"})", "application/json");
            return false;
        }
        return true;
    }

    /// RBAC-aware permission check. Falls back to legacy admin/user check if RBAC is disabled.
    bool require_permission(const httplib::Request& req, httplib::Response& res,
                            const std::string& securable_type, const std::string& operation) {
        auto session = require_auth(req, res);
        if (!session)
            return false;

        // Service-scoped tokens: check if the ITServiceOwner role grants this permission.
        // Scoped tokens cannot be used when RBAC is disabled.
        if (!session->token_scope_service.empty()) {
            if (!rbac_store_ || !rbac_store_->is_rbac_enabled()) {
                res.status = 403;
                res.set_content(R"({"error":"service-scoped tokens require RBAC to be enabled"})",
                                "application/json");
                return false;
            }
            if (!rbac_store_->check_role_has_permission("ITServiceOwner", securable_type,
                                                        operation)) {
                res.status = 403;
                res.set_content(
                    nlohmann::json({{"error", "forbidden"},
                                    {"detail", "service-scoped token does not grant " +
                                                   securable_type + ":" + operation}})
                        .dump(),
                    "application/json");
                return false;
            }
            return true;
        }

        if (rbac_store_ && rbac_store_->is_rbac_enabled()) {
            if (!rbac_store_->check_permission(session->username, securable_type, operation)) {
                res.status = 403;
                res.set_content(
                    nlohmann::json({{"error", "forbidden"},
                                    {"required_permission", securable_type + ":" + operation}})
                        .dump(),
                    "application/json");
                return false;
            }
            return true;
        }

        // Legacy fallback: write/delete/execute/approve require admin
        if (operation != "Read" && session->role != auth::Role::admin) {
            res.status = 403;
            res.set_content(R"({"error":"admin role required"})", "application/json");
            return false;
        }
        return true;
    }

    /// Scoped RBAC-aware permission check for device-specific operations.
    bool require_scoped_permission(const httplib::Request& req, httplib::Response& res,
                                   const std::string& securable_type, const std::string& operation,
                                   const std::string& agent_id) {
        auto session = require_auth(req, res);
        if (!session)
            return false;

        // Service-scoped tokens: verify the target agent belongs to the token's service,
        // and that the ITServiceOwner role grants the required permission.
        if (!session->token_scope_service.empty()) {
            if (!rbac_store_ || !rbac_store_->is_rbac_enabled()) {
                res.status = 403;
                res.set_content(R"({"error":"service-scoped tokens require RBAC to be enabled"})",
                                "application/json");
                return false;
            }
            // Check that the ITServiceOwner role grants this permission type
            if (!rbac_store_->check_role_has_permission("ITServiceOwner", securable_type,
                                                        operation)) {
                res.status = 403;
                res.set_content(
                    nlohmann::json({{"error", "forbidden"},
                                    {"detail", "service-scoped token does not grant " +
                                                   securable_type + ":" + operation}})
                        .dump(),
                    "application/json");
                return false;
            }
            // Verify the target agent's service tag matches the token's scope
            if (tag_store_ && !agent_id.empty()) {
                auto agent_service = tag_store_->get_tag(agent_id, "service");
                if (agent_service != session->token_scope_service) {
                    res.status = 403;
                    res.set_content(
                        nlohmann::json(
                            {{"error", "forbidden"},
                             {"detail", "agent is not in service '" +
                                            session->token_scope_service + "'"}})
                            .dump(),
                        "application/json");
                    return false;
                }
            }
            return true;
        }

        if (rbac_store_ && rbac_store_->is_rbac_enabled()) {
            if (!rbac_store_->check_scoped_permission(session->username, securable_type, operation,
                                                      agent_id, mgmt_group_store_.get())) {
                res.status = 403;
                res.set_content(
                    nlohmann::json({{"error", "forbidden"},
                                    {"required_permission", securable_type + ":" + operation}})
                        .dump(),
                    "application/json");
                return false;
            }
            return true;
        }

        // Legacy fallback: write/delete/execute/approve require admin
        if (operation != "Read" && session->role != auth::Role::admin) {
            res.status = 403;
            res.set_content(R"({"error":"admin role required"})", "application/json");
            return false;
        }
        return true;
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

    /// Push structured tag state to an agent via the asset_tags plugin.
    void push_asset_tags_to_agent(const std::string& agent_id) {
        if (!tag_store_)
            return;

        // Build the sync command with all 4 structured category values
        ::yuzu::agent::v1::CommandRequest cmd;
        cmd.set_command_id("asset-tag-sync-" + std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()));
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
        }
    }

    // -- HTML fragment renderers for HTMX Settings page -------------------------

    std::string render_tls_fragment() {
        std::string checked = cfg_.tls_enabled ? " checked" : "";
        std::string status_color = cfg_.tls_enabled ? "#3fb950" : "#f85149";
        std::string status_text = cfg_.tls_enabled ? "Enabled" : "Disabled";
        std::string fields_opacity = cfg_.tls_enabled ? "1" : "0.4";

        std::string cert_name =
            cfg_.tls_server_cert.empty() ? "No file" : html_escape(cfg_.tls_server_cert.string());
        std::string key_name =
            cfg_.tls_server_key.empty() ? "No file" : html_escape(cfg_.tls_server_key.string());
        std::string ca_name =
            cfg_.tls_ca_cert.empty() ? "No file" : html_escape(cfg_.tls_ca_cert.string());

        return "<form id=\"tls-form\">"
               "<div class=\"form-row\">"
               "  <label>gRPC mTLS</label>"
               "  <label class=\"toggle\">"
               "    <input type=\"checkbox\" name=\"tls_enabled\" value=\"true\"" +
               checked +
               "           hx-post=\"/api/settings/tls\" hx-target=\"#tls-feedback\""
               "           hx-swap=\"innerHTML\">"
               "    <span class=\"slider\"></span>"
               "  </label>"
               "  <span style=\"font-size:0.75rem;color:" +
               status_color + ";margin-left:0.5rem\">" + status_text +
               "</span>"
               "</div>"
               "<div style=\"margin-top:1rem;opacity:" +
               fields_opacity +
               "\">"
               "  <div class=\"form-row\">"
               "    <label>Server Certificate</label>"
               "    <div class=\"file-upload\">"
               "      <form hx-post=\"/api/settings/cert-upload\" hx-target=\"#tls-feedback\" "
               "hx-swap=\"innerHTML\""
               "            hx-encoding=\"multipart/form-data\" "
               "style=\"display:flex;align-items:center;gap:0.75rem\">"
               "        <input type=\"hidden\" name=\"type\" value=\"cert\">"
               "        <input type=\"file\" name=\"file\" accept=\".pem,.crt,.cer\""
               "               onchange=\"this.form.requestSubmit()\" style=\"display:none\" "
               "id=\"cert-file\">"
               "        <button type=\"button\" class=\"btn btn-secondary\""
               "                onclick=\"document.getElementById('cert-file').click()\">Upload "
               "PEM</button>"
               "        <span class=\"file-name\">" +
               cert_name +
               "</span>"
               "      </form>"
               "    </div>"
               "  </div>"
               "  <div class=\"form-row\">"
               "    <label>Server Private Key</label>"
               "    <div class=\"file-upload\">"
               "      <form hx-post=\"/api/settings/cert-upload\" hx-target=\"#tls-feedback\" "
               "hx-swap=\"innerHTML\""
               "            hx-encoding=\"multipart/form-data\" "
               "style=\"display:flex;align-items:center;gap:0.75rem\">"
               "        <input type=\"hidden\" name=\"type\" value=\"key\">"
               "        <input type=\"file\" name=\"file\" accept=\".pem,.key\""
               "               onchange=\"this.form.requestSubmit()\" style=\"display:none\" "
               "id=\"key-file\">"
               "        <button type=\"button\" class=\"btn btn-secondary\""
               "                onclick=\"document.getElementById('key-file').click()\">Upload "
               "PEM</button>"
               "        <span class=\"file-name\">" +
               key_name +
               "</span>"
               "      </form>"
               "    </div>"
               "  </div>"
               "  <div class=\"form-row\">"
               "    <label>CA Certificate</label>"
               "    <div class=\"file-upload\">"
               "      <form hx-post=\"/api/settings/cert-upload\" hx-target=\"#tls-feedback\" "
               "hx-swap=\"innerHTML\""
               "            hx-encoding=\"multipart/form-data\" "
               "style=\"display:flex;align-items:center;gap:0.75rem\">"
               "        <input type=\"hidden\" name=\"type\" value=\"ca\">"
               "        <input type=\"file\" name=\"file\" accept=\".pem,.crt,.cer\""
               "               onchange=\"this.form.requestSubmit()\" style=\"display:none\" "
               "id=\"ca-file\">"
               "        <button type=\"button\" class=\"btn btn-secondary\""
               "                onclick=\"document.getElementById('ca-file').click()\">Upload "
               "PEM</button>"
               "        <span class=\"file-name\">" +
               ca_name +
               "</span>"
               "      </form>"
               "    </div>"
               "  </div>"
               "</div>"
               "</form>"
               "<div class=\"feedback\" id=\"tls-feedback\"></div>";
    }

    std::string render_users_fragment() {
        auto users = auth_mgr_.list_users();
        std::string html = "<table class=\"user-table\">"
                           "  <thead><tr><th>Username</th><th>Role</th><th></th></tr></thead>"
                           "  <tbody>";

        if (users.empty()) {
            html += "<tr><td colspan=\"3\" style=\"color:#484f58\">No users</td></tr>";
        } else {
            for (const auto& u : users) {
                auto role_str = auth::role_to_string(u.role);
                auto cls = (u.role == auth::Role::admin) ? "role-admin" : "role-user";
                html += "<tr><td>" + html_escape(u.username) +
                        "</td>"
                        "<td><span class=\"role-badge " +
                        std::string(cls) + "\">" + html_escape(role_str) +
                        "</span></td>"
                        "<td><button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-delete=\"/api/settings/users/" +
                        html_escape(u.username) +
                        "\" "
                        "hx-target=\"#user-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Remove user &quot;" +
                        html_escape(u.username) +
                        "&quot;?\""
                        ">Remove</button></td></tr>";
            }
        }

        html += "  </tbody>"
                "</table>"
                "<form class=\"add-user-form\" hx-post=\"/api/settings/users\" "
                "      hx-target=\"#user-section\" hx-swap=\"innerHTML\">"
                "  <div class=\"mini-field\">"
                "    <label>Username</label>"
                "    <input type=\"text\" name=\"username\" placeholder=\"username\" required>"
                "  </div>"
                "  <div class=\"mini-field\">"
                "    <label>Password</label>"
                "    <input type=\"password\" name=\"password\" placeholder=\"password\" required>"
                "  </div>"
                "  <div class=\"mini-field\">"
                "    <label>Role</label>"
                "    <select name=\"role\">"
                "      <option value=\"user\">User</option>"
                "      <option value=\"admin\">Admin</option>"
                "    </select>"
                "  </div>"
                "  <button class=\"btn btn-primary\" type=\"submit\">Add User</button>"
                "</form>"
                "<div class=\"feedback\" id=\"user-feedback\"></div>";

        return html;
    }

    std::string render_tokens_fragment(const std::string& new_raw_token = {}) {
        auto tokens = auth_mgr_.list_enrollment_tokens();
        std::string html = "<table class=\"user-table\">"
                           "  <thead><tr><th>ID</th><th>Label</th><th>Uses</th>"
                           "  <th>Expires</th><th>Status</th><th></th></tr></thead>"
                           "  <tbody>";

        if (tokens.empty()) {
            html += "<tr><td colspan=\"6\" style=\"color:#484f58\">No tokens created</td></tr>";
        } else {
            for (const auto& t : tokens) {
                auto uses = t.max_uses == 0
                                ? std::to_string(t.use_count) + " / \xe2\x88\x9e"
                                : std::to_string(t.use_count) + " / " + std::to_string(t.max_uses);

                std::string exp;
                if (t.expires_at == (std::chrono::system_clock::time_point::max)()) {
                    exp = "Never";
                } else {
                    auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
                                     t.expires_at.time_since_epoch())
                                     .count();
                    exp = std::to_string(epoch); // epoch seconds, formatted client-side
                }

                std::string status_cls, status_txt;
                if (t.revoked) {
                    status_cls = "role-user";
                    status_txt = "Revoked";
                } else if (t.max_uses > 0 && t.use_count >= t.max_uses) {
                    status_cls = "role-user";
                    status_txt = "Exhausted";
                } else {
                    status_cls = "role-admin";
                    status_txt = "Active";
                }

                html += "<tr><td><code>" + html_escape(t.token_id) +
                        "</code></td>"
                        "<td>" +
                        html_escape(t.label) +
                        "</td>"
                        "<td>" +
                        uses +
                        "</td>"
                        "<td style=\"font-size:0.75rem\">" +
                        exp +
                        "</td>"
                        "<td><span class=\"role-badge " +
                        status_cls + "\">" + status_txt +
                        "</span></td>"
                        "<td>";
                if (!t.revoked) {
                    html += "<button class=\"btn btn-danger\" "
                            "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                            "hx-delete=\"/api/settings/enrollment-tokens/" +
                            html_escape(t.token_id) +
                            "\" "
                            "hx-target=\"#token-section\" hx-swap=\"innerHTML\" "
                            "hx-confirm=\"Revoke token &quot;" +
                            html_escape(t.token_id) +
                            "&quot;? Agents using this token will no longer be able to enroll.\""
                            ">Revoke</button>";
                }
                html += "</td></tr>";
            }
        }

        html += "  </tbody>"
                "</table>"
                "<form class=\"add-user-form\" hx-post=\"/api/settings/enrollment-tokens\" "
                "      hx-target=\"#token-section\" hx-swap=\"innerHTML\">"
                "  <div class=\"mini-field\">"
                "    <label>Label</label>"
                "    <input type=\"text\" name=\"label\" placeholder=\"e.g. NYC rollout\" "
                "style=\"width:160px\">"
                "  </div>"
                "  <div class=\"mini-field\">"
                "    <label>Max Uses</label>"
                "    <input type=\"text\" name=\"max_uses\" placeholder=\"0 = unlimited\" "
                "style=\"width:80px\">"
                "  </div>"
                "  <div class=\"mini-field\">"
                "    <label>TTL (hours)</label>"
                "    <input type=\"text\" name=\"ttl_hours\" placeholder=\"0 = never\" "
                "style=\"width:80px\">"
                "  </div>"
                "  <button class=\"btn btn-primary\" type=\"submit\">Generate Token</button>"
                "</form>"
                "<div class=\"feedback\" id=\"token-feedback\"></div>";

        // Show the one-time token reveal if a new token was just created
        if (!new_raw_token.empty()) {
            html += "<div class=\"token-reveal\">"
                    "  <div class=\"token-reveal-header\">"
                    "    COPY THIS TOKEN NOW — it will not be shown again"
                    "  </div>"
                    "  <code>" +
                    html_escape(new_raw_token) +
                    "</code><br>"
                    "  <button class=\"btn btn-secondary\" "
                    "style=\"margin-top:0.5rem;font-size:0.7rem\" "
                    "          data-copy-token>Copy to Clipboard</button>"
                    "</div>";
        }

        return html;
    }

    std::string render_api_tokens_fragment(const std::string& new_raw_token = {}) {
        if (!api_token_store_ || !api_token_store_->is_open()) {
            return "<span style=\"color:#484f58\">API token store unavailable.</span>";
        }

        // Format epoch seconds to "YYYY-MM-DD HH:MM" UTC
        auto fmt_epoch = [](int64_t epoch) -> std::string {
            if (epoch == 0)
                return "Never";
            auto tt = static_cast<std::time_t>(epoch);
            std::tm tm_buf{};
#ifdef _WIN32
            gmtime_s(&tm_buf, &tt);
#else
            gmtime_r(&tt, &tm_buf);
#endif
            char buf[32]{};
            std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tm_buf);
            return std::string(buf) + " UTC";
        };

        auto tokens = api_token_store_->list_tokens();
        std::string html = "<table class=\"user-table\">"
                           "  <thead><tr><th>ID</th><th>Name</th><th>Owner</th>"
                           "  <th>Created</th><th>Expires</th><th>Last Used</th>"
                           "  <th>Status</th><th></th></tr></thead>"
                           "  <tbody>";

        if (tokens.empty()) {
            html += "<tr><td colspan=\"8\" style=\"color:#484f58\">No API tokens created</td></tr>";
        } else {
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
            for (const auto& t : tokens) {
                std::string exp =
                    t.expires_at == 0 ? "Never" : fmt_epoch(t.expires_at);

                bool expired = t.expires_at > 0 && t.expires_at < now;

                std::string status_cls, status_txt;
                if (t.revoked) {
                    status_cls = "role-user";
                    status_txt = "Revoked";
                } else if (expired) {
                    status_cls = "role-user";
                    status_txt = "Expired";
                } else {
                    status_cls = "role-admin";
                    status_txt = "Active";
                }

                html += "<tr><td><code>" + html_escape(t.token_id) +
                        "</code></td>"
                        "<td>" +
                        html_escape(t.name) +
                        "</td>"
                        "<td>" +
                        html_escape(t.principal_id) +
                        "</td>"
                        "<td style=\"font-size:0.75rem\">" +
                        fmt_epoch(t.created_at) +
                        "</td>"
                        "<td style=\"font-size:0.75rem\">" +
                        exp +
                        "</td>"
                        "<td style=\"font-size:0.75rem\">" +
                        fmt_epoch(t.last_used_at) +
                        "</td>"
                        "<td><span class=\"role-badge " +
                        status_cls + "\">" + status_txt +
                        "</span></td>"
                        "<td>";
                if (!t.revoked) {
                    html += "<button class=\"btn btn-danger\" "
                            "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                            "hx-delete=\"/api/settings/api-tokens/" +
                            html_escape(t.token_id) +
                            "\" "
                            "hx-target=\"#api-token-section\" hx-swap=\"innerHTML\" "
                            "hx-confirm=\"Revoke API token &quot;" +
                            html_escape(t.token_id) +
                            "&quot;? Applications using this token will lose access.\""
                            ">Revoke</button>";
                }
                html += "</td></tr>";
            }
        }

        html += "  </tbody>"
                "</table>"
                "<form class=\"add-user-form\" hx-post=\"/api/settings/api-tokens\" "
                "      hx-target=\"#api-token-section\" hx-swap=\"innerHTML\">"
                "  <div class=\"mini-field\">"
                "    <label>Name</label>"
                "    <input type=\"text\" name=\"name\" placeholder=\"e.g. CI/CD pipeline\" "
                "style=\"width:160px\" required>"
                "  </div>"
                "  <div class=\"mini-field\">"
                "    <label>TTL (hours)</label>"
                "    <input type=\"text\" name=\"ttl_hours\" placeholder=\"0 = never\" "
                "style=\"width:80px\">"
                "  </div>"
                "  <button class=\"btn btn-primary\" type=\"submit\">Create Token</button>"
                "</form>"
                "<div class=\"feedback\" id=\"api-token-feedback\"></div>";

        // Show the one-time token reveal if a new token was just created
        if (!new_raw_token.empty()) {
            html += "<div class=\"token-reveal\">"
                    "  <div class=\"token-reveal-header\">"
                    "    COPY THIS API TOKEN NOW — it will not be shown again"
                    "  </div>"
                    "  <code>" +
                    html_escape(new_raw_token) +
                    "</code><br>"
                    "  <button class=\"btn btn-secondary\" "
                    "style=\"margin-top:0.5rem;font-size:0.7rem\" "
                    "          data-copy-token>Copy to Clipboard</button>"
                    "</div>";
        }

        return html;
    }

    std::string render_pending_fragment() {
        auto agents = auth_mgr_.list_pending_agents();
        std::string html = "<table class=\"user-table\">"
                           "  <thead><tr><th>Agent ID</th><th>Hostname</th><th>OS</th>"
                           "  <th>Version</th><th>Status</th><th></th></tr></thead>"
                           "  <tbody>";

        if (agents.empty()) {
            html += "<tr><td colspan=\"6\" style=\"color:#484f58\">No pending agents</td></tr>";
        } else {
            for (const auto& a : agents) {
                auto status_str = auth::pending_status_to_string(a.status);
                std::string status_cls, status_style;
                if (a.status == auth::PendingStatus::approved) {
                    status_cls = "role-admin";
                } else if (a.status == auth::PendingStatus::denied) {
                    status_cls = "role-user";
                } else {
                    status_style = "background:var(--yellow);color:#000";
                }

                // Truncate agent ID for display
                auto short_id =
                    a.agent_id.size() > 12 ? a.agent_id.substr(0, 12) + "..." : a.agent_id;

                html += "<tr>"
                        "<td><code style=\"font-size:0.7rem\">" +
                        html_escape(short_id) +
                        "</code></td>"
                        "<td>" +
                        html_escape(a.hostname) +
                        "</td>"
                        "<td>" +
                        html_escape(a.os) + " " + html_escape(a.arch) +
                        "</td>"
                        "<td>" +
                        html_escape(a.agent_version) +
                        "</td>"
                        "<td><span class=\"role-badge " +
                        status_cls + "\" style=\"" + status_style + "\">" +
                        html_escape(status_str) +
                        "</span></td>"
                        "<td>";

                if (a.status == auth::PendingStatus::pending) {
                    html += "<button class=\"btn btn-primary\" "
                            "style=\"padding:0.2rem 0.6rem;font-size:0.7rem;margin-right:0.3rem\" "
                            "hx-post=\"/api/settings/pending-agents/" +
                            html_escape(a.agent_id) +
                            "/approve\" "
                            "hx-target=\"#pending-section\" hx-swap=\"innerHTML\""
                            ">Approve</button>"
                            "<button class=\"btn btn-danger\" "
                            "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                            "hx-post=\"/api/settings/pending-agents/" +
                            html_escape(a.agent_id) +
                            "/deny\" "
                            "hx-target=\"#pending-section\" hx-swap=\"innerHTML\" "
                            "hx-confirm=\"Deny agent enrollment?\""
                            ">Deny</button>";
                } else {
                    html += "<button class=\"btn btn-secondary\" "
                            "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                            "hx-delete=\"/api/settings/pending-agents/" +
                            html_escape(a.agent_id) +
                            "\" "
                            "hx-target=\"#pending-section\" hx-swap=\"innerHTML\""
                            ">Remove</button>";
                }

                html += "</td></tr>";
            }
        }

        html += "  </tbody>"
                "</table>";

        // Bulk actions for pending agents (uses two-click confirm)
        auto pending_count = std::count_if(agents.begin(), agents.end(), [](const auto& a) {
            return a.status == auth::PendingStatus::pending;
        });
        if (pending_count > 1) {
            html += "<div style=\"margin-top:0.75rem;display:flex;gap:0.5rem\">"
                    "<button class=\"btn btn-primary\" "
                    "style=\"padding:0.3rem 0.8rem;font-size:0.75rem\" "
                    "onclick=\"twoClickConfirm(this, function() { "
                    "htmx.ajax('POST','/api/settings/pending-agents/bulk-approve',"
                    "{target:'#pending-section',swap:'innerHTML'}); })\">"
                    "Approve All (" + std::to_string(pending_count) + ")</button>"
                    "<button class=\"btn btn-danger\" "
                    "style=\"padding:0.3rem 0.8rem;font-size:0.75rem\" "
                    "onclick=\"twoClickConfirm(this, function() { "
                    "htmx.ajax('POST','/api/settings/pending-agents/bulk-deny',"
                    "{target:'#pending-section',swap:'innerHTML'}); })\">"
                    "Deny All (" + std::to_string(pending_count) + ")</button>"
                    "</div>";
        }

        html += "<div class=\"feedback\" id=\"pending-feedback\"></div>";

        return html;
    }

    std::string render_auto_approve_fragment() {
        auto rules = auto_approve_.list_rules();
        std::string html;

        // Mode selector
        html += "<div class=\"form-row\" style=\"margin-bottom:1rem\">"
                "<label>Match mode</label>"
                "<select name=\"mode\" "
                "hx-post=\"/api/settings/auto-approve/mode\" "
                "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
                "style=\"flex:0 0 auto;width:180px\">"
                "<option value=\"any\"" +
                std::string(auto_approve_.require_all() ? "" : " selected") +
                ">Any rule (first match)</option>"
                "<option value=\"all\"" +
                std::string(auto_approve_.require_all() ? " selected" : "") +
                ">All rules must match</option>"
                "</select>"
                "</div>";

        // Rules table
        html += "<table class=\"user-table\">"
                "<thead><tr><th>Type</th><th>Value</th><th>Label</th>"
                "<th>Enabled</th><th></th></tr></thead><tbody>";

        if (rules.empty()) {
            html += "<tr><td colspan=\"5\" style=\"color:#484f58\">No auto-approve rules "
                    "configured</td></tr>";
        } else {
            auto type_str = [](auth::AutoApproveRuleType t) -> std::string {
                switch (t) {
                case auth::AutoApproveRuleType::trusted_ca:
                    return "Trusted CA";
                case auth::AutoApproveRuleType::hostname_glob:
                    return "Hostname Glob";
                case auth::AutoApproveRuleType::ip_subnet:
                    return "IP Subnet";
                case auth::AutoApproveRuleType::cloud_provider:
                    return "Cloud Provider";
                }
                return "Unknown";
            };

            for (size_t i = 0; i < rules.size(); ++i) {
                const auto& r = rules[i];
                auto idx = std::to_string(i);
                html += "<tr>"
                        "<td>" +
                        html_escape(type_str(r.type)) +
                        "</td>"
                        "<td><code style=\"font-size:0.75rem\">" +
                        html_escape(r.value) +
                        "</code></td>"
                        "<td>" +
                        html_escape(r.label) +
                        "</td>"
                        "<td>"
                        "<label class=\"toggle\">"
                        "<input type=\"checkbox\"" +
                        std::string(r.enabled ? " checked" : "") +
                        " hx-post=\"/api/settings/auto-approve/" + idx +
                        "/toggle\" "
                        "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\">"
                        "<span class=\"slider\"></span></label></td>"
                        "<td><button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-delete=\"/api/settings/auto-approve/" +
                        idx +
                        "\" "
                        "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Remove this auto-approve rule?\" "
                        ">Remove</button></td></tr>";
            }
        }

        html += "</tbody></table>";

        // Add rule form
        html += "<div class=\"add-user-form\">"
                "<form hx-post=\"/api/settings/auto-approve\" "
                "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
                "style=\"display:flex;gap:0.5rem;align-items:flex-end;width:100%\">"
                "<div class=\"mini-field\">"
                "<label>Type</label>"
                "<select name=\"type\" style=\"width:140px\">"
                "<option value=\"hostname_glob\">Hostname Glob</option>"
                "<option value=\"ip_subnet\">IP Subnet</option>"
                "<option value=\"trusted_ca\">Trusted CA</option>"
                "<option value=\"cloud_provider\">Cloud Provider</option>"
                "</select></div>"
                "<div class=\"mini-field\" style=\"flex:1\">"
                "<label>Value</label>"
                "<input type=\"text\" name=\"value\" placeholder=\"*.prod.example.com\" required>"
                "</div>"
                "<div class=\"mini-field\" style=\"flex:1\">"
                "<label>Label</label>"
                "<input type=\"text\" name=\"label\" placeholder=\"Production servers\">"
                "</div>"
                "<button class=\"btn btn-primary\" type=\"submit\">Add Rule</button>"
                "</form></div>"
                "<div class=\"feedback\" id=\"auto-approve-feedback\"></div>";

        return html;
    }

    // -- Tag Compliance fragment renderer -------------------------------------

    std::string render_tag_compliance_fragment() {
        const auto& categories = get_tag_categories();

        std::string html;
        html += "<table class=\"user-table\">"
                "<thead><tr>"
                "<th>Category</th>"
                "<th>Display Name</th>"
                "<th>Agents Tagged</th>"
                "<th>Agents Missing</th>"
                "<th>Allowed Values</th>"
                "</tr></thead><tbody>";

        auto gaps = tag_store_ ? tag_store_->get_compliance_gaps()
                               : std::vector<std::pair<std::string, std::vector<std::string>>>{};

        // Count how many agents are missing each category
        std::unordered_map<std::string, int> missing_count;
        for (const auto& [agent_id, missing] : gaps) {
            for (const auto& k : missing)
                missing_count[k]++;
        }

        // Total known agents (from tags table)
        size_t total_agents = 0;
        if (tag_store_) {
            // Count via a simple query — agents that have any tag
            auto all_gaps = tag_store_->get_compliance_gaps();
            // All agents = agents with gaps + agents without gaps
            // Use distinct values approach: count agents with the first category key
            auto agents_with_any = tag_store_->get_distinct_values("role"); // rough count
            // Better: count from gaps + non-gaps
            std::unordered_set<std::string> seen;
            for (const auto& [aid, m] : gaps)
                seen.insert(aid);
            // Also agents with all tags (not in gaps)
            for (auto cat_key : kCategoryKeys) {
                auto agents = tag_store_->agents_with_tag(std::string(cat_key));
                for (const auto& a : agents)
                    seen.insert(a);
            }
            total_agents = seen.size();
        }

        for (const auto& cat : categories) {
            std::string key_str(cat.key);
            int tagged = 0;
            if (tag_store_)
                tagged = static_cast<int>(tag_store_->agents_with_tag(key_str).size());
            int missing = missing_count.count(key_str) ? missing_count[key_str] : 0;

            std::string vals_str;
            if (cat.allowed_values.empty()) {
                vals_str = "<span style=\"color:#8b949e\">Free-form</span>";
            } else {
                for (size_t i = 0; i < cat.allowed_values.size(); ++i) {
                    if (i > 0)
                        vals_str += ", ";
                    vals_str += std::string(cat.allowed_values[i]);
                }
            }

            std::string missing_style =
                missing > 0 ? "color:#f85149;font-weight:600" : "color:#3fb950";
            html += "<tr><td><code>" + key_str + "</code></td>";
            html += "<td>" + std::string(cat.display_name) + "</td>";
            html += "<td>" + std::to_string(tagged) + "</td>";
            html += "<td style=\"" + missing_style + "\">" + std::to_string(missing) + "</td>";
            html += "<td>" + vals_str + "</td></tr>";
        }

        html += "</tbody></table>";

        if (total_agents > 0) {
            size_t compliant = total_agents - gaps.size();
            html += "<div style=\"margin-top:0.75rem;font-size:0.75rem;color:#8b949e\">"
                    "Compliance: " +
                    std::to_string(compliant) + "/" + std::to_string(total_agents) +
                    " agents have all required tags</div>";
        }

        return html;
    }

    // -- Management Groups fragment renderer -----------------------------------

    std::string render_management_groups_fragment() {
        if (!mgmt_group_store_ || !mgmt_group_store_->is_open())
            return "<span style=\"color:#484f58\">Management group store not available</span>";

        auto groups = mgmt_group_store_->list_groups();

        // Build parent->children map and find roots
        std::unordered_map<std::string, std::vector<const ManagementGroup*>> children_map;
        std::vector<const ManagementGroup*> roots;
        for (const auto& g : groups) {
            if (g.parent_id.empty())
                roots.push_back(&g);
            else
                children_map[g.parent_id].push_back(&g);
        }

        // Sort roots: "All Devices" first
        std::sort(roots.begin(), roots.end(), [](const ManagementGroup* a, const ManagementGroup* b) {
            if (a->id == ManagementGroupStore::kRootGroupId)
                return true;
            if (b->id == ManagementGroupStore::kRootGroupId)
                return false;
            return a->name < b->name;
        });

        std::string html;

        // Summary row
        html += "<div style=\"margin-bottom:0.75rem;font-size:0.75rem;color:#8b949e\">"
                "Total groups: " +
                std::to_string(groups.size()) + " &middot; Total memberships: " +
                std::to_string(mgmt_group_store_->count_all_members()) + "</div>";

        // Tree table
        html += "<table class=\"user-table\">"
                "<thead><tr>"
                "<th>Group</th>"
                "<th>Type</th>"
                "<th>Members</th>"
                "<th>Actions</th>"
                "</tr></thead><tbody>";

        // Recursive tree renderer
        std::function<void(const ManagementGroup*, int)> render_node =
            [&](const ManagementGroup* g, int depth) {
                auto member_count = mgmt_group_store_->count_members(g->id);
                bool is_root = (g->id == ManagementGroupStore::kRootGroupId);

                std::string indent;
                for (int i = 0; i < depth; ++i)
                    indent += "&nbsp;&nbsp;&nbsp;&nbsp;";
                if (depth > 0)
                    indent += "<span style=\"color:#484f58\">&boxur;</span> ";

                std::string name_style = is_root ? "font-weight:600" : "";
                std::string type_badge;
                if (g->membership_type == "dynamic") {
                    type_badge = "<span style=\"background:#1f6feb;color:#fff;padding:1px 6px;"
                                 "border-radius:3px;font-size:0.7rem\">dynamic</span>";
                } else {
                    type_badge = "<span style=\"background:#484f58;color:#c9d1d9;padding:1px 6px;"
                                 "border-radius:3px;font-size:0.7rem\">static</span>";
                }

                html += "<tr>";
                html += "<td>" + indent + "<span style=\"" + name_style + "\">" + g->name +
                         "</span></td>";
                html += "<td>" + type_badge + "</td>";
                html += "<td>" + std::to_string(member_count) + "</td>";
                html += "<td>";
                // Delete button (not for root group)
                if (!is_root) {
                    html +=
                        "<button class=\"btn btn-sm\" "
                        "hx-delete=\"/api/settings/management-groups/" +
                        g->id +
                        "\" "
                        "hx-target=\"#mgmt-groups-section\" "
                        "hx-confirm=\"Delete group '" +
                        g->name +
                        "' and all children?\" "
                        "style=\"font-size:0.7rem;padding:1px 6px;color:#f85149;border-color:#f85149"
                        "\">Delete</button>";
                }
                html += "</td></tr>";

                // Render children
                auto it = children_map.find(g->id);
                if (it != children_map.end()) {
                    auto sorted_children = it->second;
                    std::sort(sorted_children.begin(), sorted_children.end(),
                              [](const ManagementGroup* a, const ManagementGroup* b) {
                                  return a->name < b->name;
                              });
                    for (const auto* child : sorted_children)
                        render_node(child, depth + 1);
                }
            };

        for (const auto* root : roots)
            render_node(root, 0);

        html += "</tbody></table>";

        // Create group form
        html +=
            "<div style=\"margin-top:0.75rem\">"
            "<details><summary style=\"cursor:pointer;color:#58a6ff;font-size:0.8rem\">"
            "Create group</summary>"
            "<form hx-post=\"/api/settings/management-groups\" "
            "hx-target=\"#mgmt-groups-section\" "
            "hx-swap=\"innerHTML\" "
            "style=\"display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:0.5rem;align-items:end\">"
            "<div><label style=\"font-size:0.7rem;color:#8b949e\">Name</label>"
            "<input type=\"text\" name=\"name\" required "
            "style=\"display:block;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;"
            "padding:4px 8px;border-radius:4px;font-size:0.8rem\"></div>"
            "<div><label style=\"font-size:0.7rem;color:#8b949e\">Parent</label>"
            "<select name=\"parent_id\" "
            "style=\"display:block;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;"
            "padding:4px 8px;border-radius:4px;font-size:0.8rem\">"
            "<option value=\"\">— root —</option>";
        for (const auto& g : groups) {
            html += "<option value=\"" + g.id + "\">" + g.name + "</option>";
        }
        html +=
            "</select></div>"
            "<div><label style=\"font-size:0.7rem;color:#8b949e\">Type</label>"
            "<select name=\"membership_type\" "
            "style=\"display:block;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;"
            "padding:4px 8px;border-radius:4px;font-size:0.8rem\">"
            "<option value=\"static\">static</option>"
            "<option value=\"dynamic\">dynamic</option>"
            "</select></div>"
            "<button type=\"submit\" class=\"btn\" "
            "style=\"font-size:0.8rem;padding:4px 12px\">Create</button>"
            "</form></details></div>";

        return html;
    }

    // -- OTA Updates fragment renderer ----------------------------------------

    std::string render_updates_fragment() {
        if (!update_registry_) {
            return "<span style=\"color:#484f58\">OTA updates are disabled "
                   "(start server with <code>--ota-enabled</code>).</span>";
        }

        auto packages = update_registry_->list_packages();
        std::string html;

        // Fleet version summary
        {
            auto agents_json_str = registry_.to_json();
            std::unordered_map<std::string, int> version_counts;
            try {
                auto arr = nlohmann::json::parse(agents_json_str);
                for (const auto& a : arr) {
                    auto v = a.value("agent_version", std::string("unknown"));
                    version_counts[v]++;
                }
            } catch (...) {}

            if (!version_counts.empty()) {
                html += "<div style=\"margin-bottom:1rem;padding:0.5rem 0.75rem;"
                        "background:#0d1117;border:1px solid #30363d;border-radius:0.3rem\">"
                        "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
                        "margin-bottom:0.3rem;text-transform:uppercase;letter-spacing:0.05em\">"
                        "Fleet Versions</div>";
                for (const auto& [ver, cnt] : version_counts) {
                    html += "<span style=\"display:inline-block;margin-right:1rem;"
                            "font-size:0.75rem\"><code>" +
                            html_escape(ver) + "</code> &times; " + std::to_string(cnt) + "</span>";
                }
                html += "</div>";
            }
        }

        // Packages table
        html += "<table class=\"user-table\">"
                "<thead><tr><th>Platform</th><th>Arch</th><th>Version</th>"
                "<th>Size</th><th>Rollout</th><th>Mandatory</th><th></th></tr></thead>"
                "<tbody>";

        if (packages.empty()) {
            html += "<tr><td colspan=\"7\" style=\"color:#484f58\">"
                    "No update packages uploaded</td></tr>";
        } else {
            for (const auto& pkg : packages) {
                auto size_str = pkg.file_size < 1024 * 1024
                                    ? std::to_string(pkg.file_size / 1024) + " KB"
                                    : std::to_string(pkg.file_size / (1024 * 1024)) + " MB";

                html += "<tr>"
                        "<td>" +
                        html_escape(pkg.platform) +
                        "</td>"
                        "<td>" +
                        html_escape(pkg.arch) +
                        "</td>"
                        "<td><code style=\"font-size:0.75rem\">" +
                        html_escape(pkg.version) +
                        "</code></td>"
                        "<td style=\"font-size:0.75rem\">" +
                        size_str +
                        "</td>"
                        "<td>"
                        "<form style=\"display:flex;align-items:center;gap:0.4rem\" "
                        "hx-post=\"/api/settings/updates/" +
                        html_escape(pkg.platform) + "/" + html_escape(pkg.arch) + "/" +
                        html_escape(pkg.version) +
                        "/rollout\" "
                        "hx-target=\"#updates-section\" hx-swap=\"innerHTML\">"
                        "<input type=\"range\" name=\"rollout_pct\" min=\"0\" max=\"100\" "
                        "value=\"" +
                        std::to_string(pkg.rollout_pct) +
                        "\" "
                        "style=\"width:60px\" "
                        "onchange=\"this.nextElementSibling.textContent=this.value+'%'\">"
                        "<span style=\"font-size:0.7rem;width:2.5em\">" +
                        std::to_string(pkg.rollout_pct) +
                        "%</span>"
                        "<button class=\"btn btn-secondary\" type=\"submit\" "
                        "style=\"padding:0.15rem 0.5rem;font-size:0.65rem\">Set</button>"
                        "</form></td>"
                        "<td style=\"font-size:0.75rem\">" +
                        std::string(pkg.mandatory ? "Yes" : "No") +
                        "</td>"
                        "<td><button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-delete=\"/api/settings/updates/" +
                        html_escape(pkg.platform) + "/" + html_escape(pkg.arch) + "/" +
                        html_escape(pkg.version) +
                        "\" "
                        "hx-target=\"#updates-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Delete update package " +
                        html_escape(pkg.version) + " for " + html_escape(pkg.platform) + "/" +
                        html_escape(pkg.arch) +
                        "?\""
                        ">Delete</button></td></tr>";
            }
        }

        html += "</tbody></table>";

        // Upload form
        html +=
            "<div class=\"add-user-form\">"
            "<form hx-post=\"/api/settings/updates/upload\" "
            "hx-target=\"#updates-section\" hx-swap=\"innerHTML\" "
            "hx-encoding=\"multipart/form-data\" "
            "style=\"display:flex;gap:0.5rem;align-items:flex-end;width:100%\">"
            "<div class=\"mini-field\">"
            "<label>Platform</label>"
            "<select name=\"platform\" style=\"width:100px\">"
            "<option value=\"windows\">Windows</option>"
            "<option value=\"linux\">Linux</option>"
            "<option value=\"darwin\">macOS</option>"
            "</select></div>"
            "<div class=\"mini-field\">"
            "<label>Arch</label>"
            "<select name=\"arch\" style=\"width:100px\">"
            "<option value=\"x86_64\">x86_64</option>"
            "<option value=\"aarch64\">aarch64</option>"
            "</select></div>"
            "<div class=\"mini-field\">"
            "<label>Binary</label>"
            "<input type=\"file\" name=\"file\" required></div>"
            "<div class=\"mini-field\">"
            "<label>Rollout %</label>"
            "<input type=\"text\" name=\"rollout_pct\" value=\"100\" style=\"width:50px\"></div>"
            "<div class=\"mini-field\" style=\"display:flex;align-items:center;gap:0.3rem\">"
            "<label>Mandatory</label>"
            "<input type=\"checkbox\" name=\"mandatory\" value=\"true\"></div>"
            "<button class=\"btn btn-primary\" type=\"submit\">Upload</button>"
            "</form></div>"
            "<div class=\"feedback\" id=\"updates-feedback\"></div>";

        return html;
    }

    // -- Compliance fragment renderers ----------------------------------------

    // Helper: return CSS class for a compliance percentage
    static const char* compliance_level(int pct) {
        if (pct >= 90) return "good";
        if (pct >= 70) return "warn";
        return "bad";
    }

    std::string render_compliance_summary_fragment() {
        // Real policy data from PolicyStore (Phase 5)
        struct PolicyRow {
            std::string id;
            std::string name;
            std::string scope;
            int pct;
            int compliant;
            int total;
            bool enabled;
        };

        std::vector<PolicyRow> policies;

        if (policy_store_ && policy_store_->is_open()) {
            auto all_policies = policy_store_->query_policies();
            for (const auto& p : all_policies) {
                auto cs = policy_store_->get_compliance_summary(p.id);
                PolicyRow row;
                row.id = p.id;
                row.name = p.name;
                row.scope = p.scope_expression;
                row.total = static_cast<int>(cs.total);
                row.compliant = static_cast<int>(cs.compliant);
                row.pct = (cs.total > 0) ? static_cast<int>(cs.compliant * 100 / cs.total) : 0;
                row.enabled = p.enabled;
                policies.push_back(std::move(row));
            }
        }

        // Fleet-level compliance from PolicyStore
        auto fc = (policy_store_ && policy_store_->is_open())
                      ? policy_store_->get_fleet_compliance()
                      : FleetCompliance{};
        int fleet_pct = static_cast<int>(fc.compliance_pct);

        std::string html;

        // Hero: fleet compliance percentage + bar
        html += "<div class=\"compliance-hero\">"
                "<div class=\"compliance-pct ";
        html += compliance_level(fleet_pct);
        html += "\">" + std::to_string(fleet_pct) + "%</div>"
                "<div class=\"compliance-bar-wrap\">"
                "<div class=\"compliance-bar\">"
                "<div class=\"compliance-fill ";
        html += compliance_level(fleet_pct);
        html += "\" style=\"width:" + std::to_string(fleet_pct) + "%\"></div>"
                "</div>"
                "<div class=\"compliance-stats\">"
                "<span><strong>" + std::to_string(static_cast<int>(policies.size())) + "</strong> policies active</span>"
                "<span><strong>" + std::to_string(static_cast<int>(fc.total_checks)) + "</strong> device checks</span>"
                "<span>Last evaluated: <strong>just now</strong></span>"
                "</div></div></div>";

        // Policy table
        html += "<table class=\"policy-table\">"
                "<thead><tr>"
                "<th>#</th><th>Policy</th><th>Scope</th>"
                "<th>Compliance</th><th></th><th></th>"
                "</tr></thead><tbody>";

        if (policies.empty()) {
            html += "<tr><td colspan=\"6\" class=\"empty-state\">"
                    "No policies defined. Create policies in the Policy Engine to track compliance."
                    "</td></tr>";
        } else {
            int row = 0;
            for (const auto& p : policies) {
                ++row;
                html += "<tr>"
                        "<td style=\"color:var(--muted)\">" + std::to_string(row) + "</td>"
                        "<td class=\"policy-name\">" + html_escape(p.name) + "</td>"
                        "<td class=\"policy-scope\">" + html_escape(p.scope) + "</td>"
                        "<td>"
                        "<span class=\"policy-pct " + std::string(compliance_level(p.pct)) + "\">"
                        + std::to_string(p.pct) + "%</span>"
                        "<div class=\"mini-bar\"><div class=\"mini-fill " + std::string(compliance_level(p.pct)) +
                        "\" style=\"width:" + std::to_string(p.pct) + "%\"></div></div>"
                        "</td>"
                        "<td style=\"font-size:0.7rem;color:var(--muted)\">"
                        + std::to_string(p.compliant) + "/" + std::to_string(p.total) +
                        "</td>"
                        "<td>"
                        "<button class=\"btn btn-secondary btn-sm\" "
                        "hx-get=\"/fragments/compliance/" + html_escape(p.id) + "\" "
                        "hx-target=\"#compliance-detail\" "
                        "hx-swap=\"innerHTML\">"
                        "View</button>"
                        "</td></tr>";
            }
        }

        html += "</tbody></table>";
        return html;
    }

    std::string render_compliance_detail_fragment(const std::string& policy_id) {
        // Look up the policy from the PolicyStore
        std::string policy_name = policy_id;
        if (policy_store_ && policy_store_->is_open()) {
            auto policy = policy_store_->get_policy(policy_id);
            if (policy)
                policy_name = policy->name;
        }

        // Get real compliance statuses from the store
        struct AgentRow {
            std::string agent_id;
            std::string hostname;
            std::string os;
            std::string status;
            std::string last_check;
            std::string detail;
        };

        std::vector<AgentRow> agents;
        if (policy_store_ && policy_store_->is_open()) {
            auto statuses = policy_store_->get_policy_agent_statuses(policy_id);
            for (const auto& s : statuses) {
                AgentRow row;
                row.agent_id = s.agent_id;
                row.status = s.status;
                row.detail = s.check_result;

                // Look up hostname/os from agent registry
                row.hostname = s.agent_id;
                row.os = "";
                try {
                    auto agents_json_str = registry_.to_json();
                    auto arr = nlohmann::json::parse(agents_json_str);
                    for (const auto& a : arr) {
                        if (a.value("agent_id", std::string{}) == s.agent_id) {
                            row.hostname = a.value("hostname", s.agent_id);
                            row.os = a.value("os", std::string{});
                            break;
                        }
                    }
                } catch (...) {}

                // Format last_check as relative time
                if (s.last_check_at > 0) {
                    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
                    auto delta = now - s.last_check_at;
                    if (delta < 60) row.last_check = std::to_string(delta) + "s ago";
                    else if (delta < 3600) row.last_check = std::to_string(delta / 60) + " min ago";
                    else row.last_check = std::to_string(delta / 3600) + "h ago";
                } else {
                    row.last_check = "never";
                }

                agents.push_back(std::move(row));
            }
        }

        if (agents.empty()) {
            return "<div class=\"detail-panel\">"
                   "<h3>" + html_escape(policy_name) +
                   " <span style=\"font-size:0.7rem;font-weight:400;color:var(--muted)\">"
                   "(" + html_escape(policy_id) + ")</span></h3>"
                   "<div class=\"empty-state\">No compliance data yet. "
                   "Agents will report status once the policy triggers fire.</div></div>";
        }

        // Count statuses
        int compliant = 0, non_compliant = 0, unknown = 0, fixing = 0, error_count = 0;
        for (const auto& a : agents) {
            if (a.status == "compliant") ++compliant;
            else if (a.status == "non_compliant") ++non_compliant;
            else if (a.status == "unknown") ++unknown;
            else if (a.status == "fixing") ++fixing;
            else if (a.status == "error") ++error_count;
        }

        std::string html;
        html += "<div class=\"detail-panel\">"
                "<h3>" + html_escape(policy_name) +
                " <span style=\"font-size:0.7rem;font-weight:400;color:var(--muted)\">"
                "(" + html_escape(policy_id) + ")</span></h3>";

        // Status summary badges
        html += "<div style=\"display:flex;gap:1rem;margin-bottom:0.75rem;font-size:0.75rem\">"
                "<span class=\"status-compliant\">" + std::to_string(compliant) + " compliant</span>"
                "<span class=\"status-non-compliant\">" + std::to_string(non_compliant) + " non-compliant</span>"
                "<span class=\"status-pending-eval\">" + std::to_string(unknown) + " unknown</span>"
                "<span class=\"status-remediated\">" + std::to_string(fixing) + " fixing</span>"
                "</div>";

        // Per-agent table
        html += "<table class=\"detail-table\">"
                "<thead><tr>"
                "<th>Agent</th><th>Hostname</th><th>OS</th>"
                "<th>Status</th><th>Last Check</th><th>Detail</th>"
                "</tr></thead><tbody>";

        for (const auto& a : agents) {
            std::string status_class = "status-compliant";
            if (a.status == "non_compliant") status_class = "status-non-compliant";
            else if (a.status == "unknown") status_class = "status-pending-eval";
            else if (a.status == "fixing") status_class = "status-remediated";
            else if (a.status == "error") status_class = "status-non-compliant";

            std::string status_label = a.status;
            if (status_label == "non_compliant") status_label = "Non-Compliant";
            else if (status_label == "compliant") status_label = "Compliant";
            else if (status_label == "unknown") status_label = "Unknown";
            else if (status_label == "fixing") status_label = "Fixing";
            else if (status_label == "error") status_label = "Error";

            html += "<tr>"
                    "<td style=\"font-family:var(--mono);font-size:0.7rem;color:var(--yellow)\">"
                    + html_escape(a.agent_id) + "</td>"
                    "<td>" + html_escape(a.hostname) + "</td>"
                    "<td style=\"font-size:0.75rem;color:var(--muted)\">" + html_escape(a.os) + "</td>"
                    "<td><span class=\"" + status_class + "\">" + status_label + "</span></td>"
                    "<td style=\"font-size:0.7rem;color:var(--muted)\">" + html_escape(a.last_check) + "</td>"
                    "<td style=\"font-size:0.75rem\">" + html_escape(a.detail) + "</td>"
                    "</tr>";
        }

        html += "</tbody></table></div>";
        return html;
    }

    // -- Web server -----------------------------------------------------------

    // Cookie attribute helper — adds Secure flag when HTTPS is enabled
    std::string session_cookie_attrs() const {
        std::string attrs = "; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800";
        if (cfg_.https_enabled) {
            attrs += "; Secure";
        }
        return attrs;
    }

    // Audit helper — extract context from HTTP request
    AuditEvent make_audit_event(const httplib::Request& req, const std::string& action,
                                const std::string& result) {
        AuditEvent event;
        event.action = action;
        event.result = result;
        event.source_ip = req.remote_addr;
        event.user_agent = req.get_header_value("User-Agent");

        // Extract principal from session
        auto token = extract_session_cookie(req);
        auto session = auth_mgr_.validate_session(token);
        if (session) {
            event.principal = session->username;
            event.principal_role = auth::role_to_string(session->role);
            event.session_id = token;
        }
        return event;
    }

    void audit_log(const httplib::Request& req, const std::string& action,
                   const std::string& result, const std::string& target_type = {},
                   const std::string& target_id = {}, const std::string& detail = {}) {
        if (!audit_store_)
            return;
        auto event = make_audit_event(req, action, result);
        event.target_type = target_type;
        event.target_id = target_id;
        event.detail = detail;
        audit_store_->log(event);
    }

    // Analytics helper — emit an analytics event with HTTP request context
    void emit_event(const std::string& event_type, const httplib::Request& req,
                    const nlohmann::json& attrs = {}, const nlohmann::json& payload_data = {},
                    Severity sev = Severity::kInfo) {
        if (!analytics_store_)
            return;
        AnalyticsEvent ae;
        ae.event_type = event_type;
        ae.severity = sev;
        ae.attributes = attrs;
        ae.payload = payload_data;

        auto token = extract_session_cookie(req);
        auto session = auth_mgr_.validate_session(token);
        if (session) {
            ae.principal = session->username;
            ae.principal_role = auth::role_to_string(session->role);
            ae.session_id = token;
        }
        analytics_store_->emit(std::move(ae));
    }

    void start_web_server() {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        if (cfg_.https_enabled) {
            if (cfg_.https_cert_path.empty() || cfg_.https_key_path.empty()) {
                spdlog::error("HTTPS enabled but --https-cert and --https-key are required");
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
            web_server_ = std::make_unique<httplib::SSLServer>(
                cfg_.https_cert_path.string().c_str(), cfg_.https_key_path.string().c_str());
            spdlog::info("HTTPS enabled on port {} (cert: {}, key: {})", cfg_.https_port,
                         cfg_.https_cert_path.string(), cfg_.https_key_path.string());
        } else {
            web_server_ = std::make_unique<httplib::Server>();
        }
#else
        if (cfg_.https_enabled) {
            spdlog::warn(
                "HTTPS requested but OpenSSL support not compiled in; falling back to HTTP");
        }
        web_server_ = std::make_unique<httplib::Server>();
#endif

        // -- Auth middleware (pre-routing) -----------------------------------
        web_server_->set_pre_routing_handler(
            [this](const httplib::Request& req,
                   httplib::Response& res) -> httplib::Server::HandlerResponse {
                // Allow unauthenticated access to login page, metrics, health, and OIDC flow
                if (req.path == "/login" || req.path == "/metrics" || req.path == "/health" ||
                    req.path == "/auth/oidc/start" || req.path == "/auth/callback" ||
                    req.path.starts_with("/static/")) {
                    return httplib::Server::HandlerResponse::Unhandled;
                }

                // Check session cookie
                auto token = extract_session_cookie(req);
                auto session = auth_mgr_.validate_session(token);

                // If no session cookie, try API token auth (Bearer or X-Yuzu-Token)
                if (!session && api_token_store_) {
                    auto auth_header = req.get_header_value("Authorization");
                    if (auth_header.size() > 7 && auth_header.substr(0, 7) == "Bearer ") {
                        auto api_token = api_token_store_->validate_token(auth_header.substr(7));
                        if (api_token) session.emplace();
                    }
                    if (!session) {
                        auto custom_header = req.get_header_value("X-Yuzu-Token");
                        if (!custom_header.empty()) {
                            auto api_token = api_token_store_->validate_token(custom_header);
                            if (api_token) session.emplace();
                        }
                    }
                }

                if (!session) {
                    // API calls get 401, pages get redirect
                    if (req.path.starts_with("/api/") || req.path == "/events") {
                        res.status = 401;
                        res.set_content(R"({"error":"unauthorized"})", "application/json");
                    } else {
                        res.set_redirect("/login");
                    }
                    return httplib::Server::HandlerResponse::Handled;
                }

                return httplib::Server::HandlerResponse::Unhandled;
            });

        // -- Login page -------------------------------------------------------
        web_server_->Get("/login", [this](const httplib::Request& req, httplib::Response& res) {
            std::string html(kLoginHtml);
            // Inject OIDC enablement flag into the page
            if (oidc_provider_ && oidc_provider_->is_enabled()) {
                auto pos = html.find("/*OIDC_CONFIG*/");
                if (pos != std::string::npos)
                    html.replace(pos, 15, "window.OIDC_ENABLED=true;");
            }
            res.set_content(html, "text/html; charset=utf-8");
        });

        web_server_->Post("/login", [this](const httplib::Request& req, httplib::Response& res) {
            auto username = extract_form_value(req.body, "username");
            auto password = extract_form_value(req.body, "password");

            auto token = auth_mgr_.authenticate(username, password);
            if (!token) {
                res.status = 401;
                res.set_content(R"({"error":"Invalid username or password"})", "application/json");
                audit_log(req, "auth.login_failed", "failure", "user", username);
                emit_event("auth.login_failed", req,
                           {{"source_ip", req.remote_addr}, {"username", username}}, {},
                           Severity::kWarn);
                return;
            }

            res.set_header("Set-Cookie", "yuzu_session=" + *token + session_cookie_attrs());
            res.set_content(R"({"status":"ok"})", "application/json");
            audit_log(req, "auth.login", "success", "user", username);
            emit_event("auth.login", req,
                       {{"source_ip", req.remote_addr},
                        {"user_agent", req.get_header_value("User-Agent")}});
        });

        // -- Logout -----------------------------------------------------------
        web_server_->Post("/logout", [this](const httplib::Request& req, httplib::Response& res) {
            audit_log(req, "auth.logout", "success");
            emit_event("auth.logout", req);
            auto token = extract_session_cookie(req);
            if (!token.empty()) {
                auth_mgr_.invalidate_session(token);
            }
            res.set_header("Set-Cookie",
                           "yuzu_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
            res.set_content(R"({"status":"ok"})", "application/json");
        });

        // -- OIDC SSO endpoints -----------------------------------------------
        web_server_->Get(
            "/auth/oidc/start", [this](const httplib::Request& req, httplib::Response& res) {
                if (!oidc_provider_ || !oidc_provider_->is_enabled()) {
                    res.status = 404;
                    res.set_content(R"({"error":"OIDC not configured"})", "application/json");
                    return;
                }
                // Derive redirect URI from the request Host header so OIDC works
                // regardless of which IP/hostname the operator used to reach us.
                auto host = req.get_header_value("Host");
                std::string redirect_uri;
                if (!host.empty()) {
                    auto scheme = cfg_.https_enabled ? "https" : "http";
                    redirect_uri = std::string(scheme) + "://" + host + "/auth/callback";
                }
                auto auth_url = oidc_provider_->start_auth_flow(redirect_uri);
                res.set_redirect(auth_url);
            });

        web_server_->Get("/auth/callback", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
            if (!oidc_provider_) {
                res.status = 404;
                res.set_content("OIDC not configured", "text/plain");
                return;
            }

            // Check for error response from IdP
            auto error = req.get_param_value("error");
            if (!error.empty()) {
                auto desc = req.get_param_value("error_description");
                spdlog::warn("OIDC error from IdP: {} - {}", error, desc);
                res.set_redirect("/login?error=sso_denied");
                return;
            }

            auto code = req.get_param_value("code");
            auto state = req.get_param_value("state");

            if (code.empty() || state.empty()) {
                res.set_redirect("/login?error=sso_invalid");
                return;
            }

            auto result = oidc_provider_->handle_callback(code, state);
            if (!result) {
                spdlog::warn("OIDC callback failed: {}", result.error());
                audit_log(req, "auth.oidc_login_failed", "failure");
                emit_event("auth.oidc_login_failed", req,
                           {{"source_ip", req.remote_addr}, {"error", result.error()}}, {},
                           Severity::kWarn);
                res.set_redirect("/login?error=sso_failed");
                return;
            }

            auto& claims = result.value();
            auto email = claims.email.empty() ? claims.preferred_username : claims.email;
            auto display = claims.name.empty() ? email : claims.name;
            auto admin_gid = oidc_provider_ ? cfg_.oidc_admin_group : std::string{};
            auto session_token =
                auth_mgr_.create_oidc_session(display, email, claims.sub, claims.groups, admin_gid);

            // Sync Entra groups into the RBAC store so that group-scoped role
            // assignments (e.g. ApiTokenManager on an Entra group) take effect.
            if (rbac_store_ && !claims.groups.empty()) {
                auto username = display.empty() ? email : display;
                for (const auto& gid : claims.groups) {
                    (void)rbac_store_->create_group({.name = gid,
                                                     .description = "Entra ID group (auto-synced)",
                                                     .source = "entra",
                                                     .external_id = gid});
                    (void)rbac_store_->add_group_member(gid, username);
                }
            }

            res.set_header("Set-Cookie", "yuzu_session=" + session_token + session_cookie_attrs());

            audit_log(req, "auth.oidc_login", "success", "user", display);
            emit_event("auth.oidc_login", req,
                       {{"source_ip", req.remote_addr},
                        {"oidc_sub", claims.sub},
                        {"email", email},
                        {"name", claims.name}});

            res.set_redirect("/");
        });

        // -- HTTP metrics (post-routing handler) --------------------------------
        web_server_->set_post_routing_handler(
            [this](const httplib::Request& req, httplib::Response& res) {
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

        // -- Current user info (/api/me) --------------------------------------
        web_server_->Get("/api/me", [this](const httplib::Request& req, httplib::Response& res) {
            auto session = require_auth(req, res);
            if (!session)
                return;
            auto j = nlohmann::json({{"username", session->username},
                                     {"role", auth::role_to_string(session->role)}});
            // Add RBAC role if enabled
            if (rbac_store_ && rbac_store_->is_rbac_enabled()) {
                j["rbac_enabled"] = true;
                auto roles = rbac_store_->get_principal_roles("user", session->username);
                if (!roles.empty()) {
                    j["rbac_role"] = roles[0].role_name;
                } else {
                    // Fallback: map legacy role to RBAC role name
                    j["rbac_role"] = session->role == auth::Role::admin ? "Administrator" : "Viewer";
                }
            } else {
                j["rbac_enabled"] = false;
                j["rbac_role"] = session->role == auth::Role::admin ? "Administrator" : "Viewer";
            }
            res.set_content(j.dump(), "application/json");
        });

        // -- Static design-system assets ----------------------------------------
        web_server_->Get("/static/yuzu.css",
                         [](const httplib::Request&, httplib::Response& res) {
                             res.set_header("Cache-Control", "public, max-age=3600");
                             res.set_content(kYuzuCss, "text/css; charset=utf-8");
                         });
        web_server_->Get("/static/icons.svg",
                         [](const httplib::Request&, httplib::Response& res) {
                             res.set_header("Cache-Control", "public, max-age=3600");
                             res.set_content(kYuzuIconsSvg, "image/svg+xml");
                         });

        // -- Dashboard (unified UI) -------------------------------------------
        web_server_->Get("/", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(kDashboardIndexHtml, "text/html; charset=utf-8");
        });

        // -- Settings page (admin only) ---------------------------------------
        web_server_->Get("/settings", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_admin(req, res)) {
                res.set_redirect("/");
                return;
            }
            res.set_content(kSettingsHtml, "text/html; charset=utf-8");
        });

        // -- Settings HTMX fragment endpoints -----------------------------------

        web_server_->Get("/fragments/settings/tls",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_admin(req, res))
                                 return;
                             res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
                         });

        web_server_->Get("/fragments/settings/users",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_admin(req, res))
                                 return;
                             res.set_content(render_users_fragment(), "text/html; charset=utf-8");
                         });

        web_server_->Get("/fragments/settings/tokens",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_admin(req, res))
                                 return;
                             res.set_content(render_tokens_fragment(), "text/html; charset=utf-8");
                         });

        web_server_->Get("/fragments/settings/pending",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_admin(req, res))
                                 return;
                             res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
                         });

        web_server_->Get("/fragments/settings/auto-approve", [this](const httplib::Request& req,
                                                                    httplib::Response& res) {
            if (!require_admin(req, res))
                return;
            res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
        });

        web_server_->Get("/fragments/settings/api-tokens",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "ApiToken", "Read"))
                                 return;
                             res.set_content(render_api_tokens_fragment(),
                                             "text/html; charset=utf-8");
                         });

        // -- Settings API: TLS toggle (HTMX POST) ----------------------------
        web_server_->Post("/api/settings/tls",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_admin(req, res))
                                  return;
                              // HTMX sends form-encoded: tls_enabled=true (or absent if unchecked)
                              auto val = extract_form_value(req.body, "tls_enabled");
                              cfg_.tls_enabled = (val == "true");
                              spdlog::info("TLS setting changed to {} (restart required)",
                                           cfg_.tls_enabled ? "enabled" : "disabled");
                              // Return updated TLS fragment
                              res.set_header("HX-Retarget", "#tls-section");
                              res.set_header("HX-Trigger",
                                  R"({"showToast":{"message":"TLS settings saved","level":"success"}})");
                              res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
                          });

        // -- Settings API: Certificate upload (admin only, multipart) ----------
        web_server_->Post("/api/settings/cert-upload", [this](const httplib::Request& req,
                                                              httplib::Response& res) {
            if (!require_admin(req, res))
                return;

            // HTMX sends multipart/form-data with "type" hidden field and "file" file input
            std::string type;
            std::string content;

            if (req.form.has_field("type")) {
                type = req.form.get_field("type");
            } else if (req.has_param("type")) {
                type = req.get_param_value("type");
            }

            if (req.form.has_file("file")) {
                content = req.form.get_file("file").content;
            }

            if (type.empty() || content.empty()) {
                res.status = 400;
                res.set_content("<span class=\"feedback-error\">Type and file are required.</span>",
                                "text/html; charset=utf-8");
                return;
            }

            // Ensure cert dir exists
            auto cert_dir = auth::default_cert_dir();
            std::error_code ec;
            std::filesystem::create_directories(cert_dir, ec);
            if (ec) {
                res.status = 500;
                res.set_content(
                    "<span class=\"feedback-error\">Cannot create cert directory.</span>",
                    "text/html; charset=utf-8");
                return;
            }

            // Determine output filename
            std::string out_name;
            if (type == "cert")
                out_name = "server.pem";
            else if (type == "key")
                out_name = "server-key.pem";
            else if (type == "ca")
                out_name = "ca.pem";
            else {
                res.status = 400;
                res.set_content(
                    "<span class=\"feedback-error\">Type must be cert, key, or ca.</span>",
                    "text/html; charset=utf-8");
                return;
            }

            auto out_path = cert_dir / out_name;
            {
                std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
                if (!f.is_open()) {
                    res.status = 500;
                    res.set_content("<span class=\"feedback-error\">Cannot write cert file.</span>",
                                    "text/html; charset=utf-8");
                    return;
                }
                f.write(content.data(), static_cast<std::streamsize>(content.size()));
            }

            // Update config
            if (type == "cert")
                cfg_.tls_server_cert = out_path;
            else if (type == "key")
                cfg_.tls_server_key = out_path;
            else if (type == "ca")
                cfg_.tls_ca_cert = out_path;

            spdlog::info("Certificate uploaded: {} → {}", type, out_path.string());
            // Re-render TLS section to show new file paths
            res.set_header("HX-Retarget", "#tls-section");
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Certificate uploaded","level":"success"}})");
            res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
        });

        // -- Settings API: User management (admin only, HTMX) ------------------
        web_server_->Post(
            "/api/settings/users", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res))
                    return;
                auto username = extract_form_value(req.body, "username");
                auto password = extract_form_value(req.body, "password");
                auto role_str = extract_form_value(req.body, "role");

                if (username.empty() || password.empty()) {
                    res.status = 400;
                    res.set_content(render_users_fragment() +
                                        "<script>document.getElementById('user-feedback')."
                                        "className='feedback feedback-error';"
                                        "document.getElementById('user-feedback').textContent='"
                                        "Username and password required.';</script>",
                                    "text/html; charset=utf-8");
                    return;
                }

                auto role = auth::string_to_role(role_str);
                auth_mgr_.upsert_user(username, password, role);
                if (!auth_mgr_.save_config()) {
                    spdlog::error("Failed to save config after user upsert");
                }
                spdlog::info("User '{}' added/updated (role={})", username, role_str);
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"User created","level":"success"}})");
                res.set_content(render_users_fragment(), "text/html; charset=utf-8");
            });

        // DELETE /api/settings/users/:username
        web_server_->Delete(R"(/api/settings/users/(.+))", [this](const httplib::Request& req,
                                                                  httplib::Response& res) {
            if (!require_admin(req, res))
                return;
            auto username = req.matches[1].str();
            if (auth_mgr_.remove_user(username)) {
                if (!auth_mgr_.save_config()) {
                    spdlog::error("Failed to save config after user removal");
                }
                spdlog::info("User '{}' removed", username);
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"User deleted","level":"success"}})");
            }
            res.set_content(render_users_fragment(), "text/html; charset=utf-8");
        });

        // -- Settings API: Enrollment tokens (admin only, HTMX) ----------------

        web_server_->Post("/api/settings/enrollment-tokens", [this](const httplib::Request& req,
                                                                    httplib::Response& res) {
            if (!require_admin(req, res))
                return;
            auto label = extract_form_value(req.body, "label");
            auto max_uses_s = extract_form_value(req.body, "max_uses");
            auto ttl_s = extract_form_value(req.body, "ttl_hours");

            int max_uses = 0;
            int ttl_hours = 0;
            try {
                if (!max_uses_s.empty())
                    max_uses = std::stoi(max_uses_s);
                if (!ttl_s.empty())
                    ttl_hours = std::stoi(ttl_s);
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(R"({"error":"invalid numeric parameter"})", "application/json");
                return;
            }

            auto ttl =
                ttl_hours > 0 ? std::chrono::seconds(ttl_hours * 3600) : std::chrono::seconds(0);

            auto raw_token = auth_mgr_.create_enrollment_token(label, max_uses, ttl);

            // Return token list fragment with the one-time token reveal
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Enrollment token created","level":"success"}})");
            res.set_content(render_tokens_fragment(raw_token), "text/html; charset=utf-8");
        });

        web_server_->Delete(R"(/api/settings/enrollment-tokens/(.+))",
                            [this](const httplib::Request& req, httplib::Response& res) {
                                if (!require_admin(req, res))
                                    return;
                                auto token_id = req.matches[1].str();
                                auth_mgr_.revoke_enrollment_token(token_id);
                                res.set_header("HX-Trigger",
                                    R"({"showToast":{"message":"Enrollment token revoked","level":"success"}})");
                                res.set_content(render_tokens_fragment(),
                                                "text/html; charset=utf-8");
                            });

        // -- Batch enrollment token generation (JSON API for scripting) ---------
        web_server_->Post("/api/settings/enrollment-tokens/batch", [this](
                                                                       const httplib::Request& req,
                                                                       httplib::Response& res) {
            if (!require_admin(req, res))
                return;
            auto label = extract_json_string(req.body, "label");
            auto count_s = extract_json_string(req.body, "count");
            auto max_uses_s = extract_json_string(req.body, "max_uses");
            auto ttl_s = extract_json_string(req.body, "ttl_hours");

            int count = 10;
            int max_uses = 1;
            int ttl_hours = 0;
            try {
                if (!count_s.empty())
                    count = std::stoi(count_s);
                if (!max_uses_s.empty())
                    max_uses = std::stoi(max_uses_s);
                if (!ttl_s.empty())
                    ttl_hours = std::stoi(ttl_s);
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(R"({"error":"invalid numeric parameter"})", "application/json");
                return;
            }

            if (count < 1 || count > 10000) {
                res.status = 400;
                res.set_content(R"({"error":"count must be 1-10000"})", "application/json");
                return;
            }

            auto ttl =
                ttl_hours > 0 ? std::chrono::seconds(ttl_hours * 3600) : std::chrono::seconds(0);

            auto tokens = auth_mgr_.create_enrollment_tokens_batch(label, count, max_uses, ttl);

            // Return JSON array for scripting/Ansible consumption
            res.set_content(nlohmann::json({{"count", tokens.size()}, {"tokens", tokens}}).dump(),
                            "application/json");
        });

        // -- Settings API: API tokens (admin only, HTMX) -------------------------

        web_server_->Post("/api/settings/api-tokens", [this](const httplib::Request& req,
                                                             httplib::Response& res) {
            if (!require_permission(req, res, "ApiToken", "Write"))
                return;
            auto session = require_auth(req, res);
            if (!session)
                return;

            auto name = extract_form_value(req.body, "name");
            auto ttl_s = extract_form_value(req.body, "ttl_hours");

            if (name.empty()) {
                res.set_content(
                    "<span class=\"feedback-error\">Token name is required.</span>",
                    "text/html; charset=utf-8");
                return;
            }

            int64_t expires_at = 0;
            if (!ttl_s.empty()) {
                try {
                    int ttl_hours = std::stoi(ttl_s);
                    if (ttl_hours > 0) {
                        auto now = std::chrono::duration_cast<std::chrono::seconds>(
                                       std::chrono::system_clock::now().time_since_epoch())
                                       .count();
                        expires_at = now + static_cast<int64_t>(ttl_hours) * 3600;
                    }
                } catch (const std::exception&) {
                    res.set_content(
                        "<span class=\"feedback-error\">Invalid TTL value.</span>",
                        "text/html; charset=utf-8");
                    return;
                }
            }

            auto result = api_token_store_->create_token(name, session->username, expires_at);
            if (!result) {
                res.set_content(
                    "<span class=\"feedback-error\">" + html_escape(result.error()) + "</span>",
                    "text/html; charset=utf-8");
                return;
            }

            spdlog::info("API token '{}' created by {}", name, session->username);

            if (audit_store_) {
                audit_store_->log({.principal = session->username,
                                   .principal_role = "admin",
                                   .action = "api_token.create",
                                   .target_type = "ApiToken",
                                   .target_id = name,
                                   .source_ip = req.remote_addr,
                                   .result = "success"});
            }

            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"API token created","level":"success"}})");
            res.set_content(render_api_tokens_fragment(result.value()),
                            "text/html; charset=utf-8");
        });

        web_server_->Delete(R"(/api/settings/api-tokens/(.+))",
                            [this](const httplib::Request& req, httplib::Response& res) {
                                if (!require_permission(req, res, "ApiToken", "Delete"))
                                    return;
                                auto session = require_auth(req, res);
                                if (!session)
                                    return;
                                auto token_id = req.matches[1].str();
                                api_token_store_->revoke_token(token_id);

                                spdlog::info("API token '{}' revoked by {}", token_id,
                                             session->username);

                                if (audit_store_) {
                                    audit_store_->log({.principal = session->username,
                                                       .principal_role = "admin",
                                                       .action = "api_token.revoke",
                                                       .target_type = "ApiToken",
                                                       .target_id = token_id,
                                                       .source_ip = req.remote_addr,
                                                       .result = "success"});
                                }

                                res.set_header("HX-Trigger",
                                    R"({"showToast":{"message":"API token revoked","level":"success"}})");
                                res.set_content(render_api_tokens_fragment(),
                                                "text/html; charset=utf-8");
                            });

        // -- Settings API: Pending agents (admin only, HTMX) --------------------

        // Bulk approve/deny — must be registered BEFORE the (.+) catch-all patterns
        web_server_->Post("/api/settings/pending-agents/bulk-approve",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_admin(req, res))
                                  return;
                              int count = 0;
                              for (const auto& a : auth_mgr_.list_pending_agents()) {
                                  if (a.status == auth::PendingStatus::pending) {
                                      auth_mgr_.approve_pending_agent(a.agent_id);
                                      ++count;
                                  }
                              }
                              spdlog::info("Bulk approved {} pending agent(s)", count);
                              res.set_header("HX-Trigger",
                                  R"({"showToast":{"message":")" + std::to_string(count) +
                                  R"( agent(s) approved","level":"success"}})");
                              res.set_content(render_pending_fragment(),
                                              "text/html; charset=utf-8");
                          });

        web_server_->Post("/api/settings/pending-agents/bulk-deny",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_admin(req, res))
                                  return;
                              int count = 0;
                              for (const auto& a : auth_mgr_.list_pending_agents()) {
                                  if (a.status == auth::PendingStatus::pending) {
                                      auth_mgr_.deny_pending_agent(a.agent_id);
                                      ++count;
                                  }
                              }
                              spdlog::info("Bulk denied {} pending agent(s)", count);
                              res.set_header("HX-Trigger",
                                  R"({"showToast":{"message":")" + std::to_string(count) +
                                  R"( agent(s) denied","level":"warning"}})");
                              res.set_content(render_pending_fragment(),
                                              "text/html; charset=utf-8");
                          });

        web_server_->Post(R"(/api/settings/pending-agents/(.+)/approve)",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_admin(req, res))
                                  return;
                              auto agent_id = req.matches[1].str();
                              auth_mgr_.approve_pending_agent(agent_id);
                              res.set_header("HX-Trigger",
                                  R"({"showToast":{"message":"Agent approved","level":"success"}})");
                              res.set_content(render_pending_fragment(),
                                              "text/html; charset=utf-8");
                          });

        web_server_->Post(R"(/api/settings/pending-agents/(.+)/deny)",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_admin(req, res))
                                  return;
                              auto agent_id = req.matches[1].str();
                              auth_mgr_.deny_pending_agent(agent_id);
                              res.set_header("HX-Trigger",
                                  R"({"showToast":{"message":"Agent denied","level":"warning"}})");
                              res.set_content(render_pending_fragment(),
                                              "text/html; charset=utf-8");
                          });

        web_server_->Delete(R"(/api/settings/pending-agents/(.+))",
                            [this](const httplib::Request& req, httplib::Response& res) {
                                if (!require_admin(req, res))
                                    return;
                                auto agent_id = req.matches[1].str();
                                auth_mgr_.remove_pending_agent(agent_id);
                                res.set_content(render_pending_fragment(),
                                                "text/html; charset=utf-8");
                            });

        // -- Settings API: Auto-approve rules (HTMX) -------------------------

        // Add a new rule
        web_server_->Post("/api/settings/auto-approve", [this](const httplib::Request& req,
                                                               httplib::Response& res) {
            if (!require_admin(req, res))
                return;
            auto type_s = extract_form_value(req.body, "type");
            auto value = extract_form_value(req.body, "value");
            auto label = extract_form_value(req.body, "label");

            auth::AutoApproveRuleType type;
            if (type_s == "trusted_ca")
                type = auth::AutoApproveRuleType::trusted_ca;
            else if (type_s == "ip_subnet")
                type = auth::AutoApproveRuleType::ip_subnet;
            else if (type_s == "cloud_provider")
                type = auth::AutoApproveRuleType::cloud_provider;
            else
                type = auth::AutoApproveRuleType::hostname_glob;

            auto_approve_.add_rule({type, value, label, true});
            spdlog::info("Auto-approve rule added: {}:{} ({})", type_s, value, label);
            res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
        });

        // Change mode (any/all)
        web_server_->Post("/api/settings/auto-approve/mode", [this](const httplib::Request& req,
                                                                    httplib::Response& res) {
            if (!require_admin(req, res))
                return;
            auto mode = extract_form_value(req.body, "mode");
            auto_approve_.set_require_all(mode == "all");
            auto_approve_.save();
            spdlog::info("Auto-approve mode changed to {}", mode);
            res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
        });

        // Toggle rule enabled/disabled
        web_server_->Post(R"(/api/settings/auto-approve/(\d+)/toggle)",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_admin(req, res))
                                  return;
                              auto idx = static_cast<size_t>(std::stoul(req.matches[1].str()));
                              auto rules = auto_approve_.list_rules();
                              if (idx < rules.size()) {
                                  auto_approve_.set_enabled(idx, !rules[idx].enabled);
                              }
                              res.set_content(render_auto_approve_fragment(),
                                              "text/html; charset=utf-8");
                          });

        // Remove a rule
        web_server_->Delete(R"(/api/settings/auto-approve/(\d+))",
                            [this](const httplib::Request& req, httplib::Response& res) {
                                if (!require_admin(req, res))
                                    return;
                                auto idx = static_cast<size_t>(std::stoul(req.matches[1].str()));
                                auto_approve_.remove_rule(idx);
                                spdlog::info("Auto-approve rule {} removed", idx);
                                res.set_content(render_auto_approve_fragment(),
                                                "text/html; charset=utf-8");
                            });

        // -- Settings HTMX fragment: Management Groups ----------------------------

        web_server_->Get("/fragments/settings/management-groups",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "ManagementGroup", "Read"))
                                 return;
                             res.set_content(render_management_groups_fragment(),
                                             "text/html; charset=utf-8");
                         });

        web_server_->Post("/api/settings/management-groups",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_permission(req, res, "ManagementGroup", "Write"))
                                  return;
                              auto name = extract_form_value(req.body, "name");
                              auto parent_id = extract_form_value(req.body, "parent_id");
                              auto mtype = extract_form_value(req.body, "membership_type");
                              if (name.empty()) {
                                  res.set_content(
                                      "<span class=\"feedback-error\">Name required</span>",
                                      "text/html; charset=utf-8");
                                  return;
                              }
                              ManagementGroup g;
                              g.name = name;
                              g.parent_id = parent_id;
                              g.membership_type = mtype.empty() ? "static" : mtype;
                              auto session = require_auth(req, res);
                              if (session)
                                  g.created_by = session->username;
                              auto result = mgmt_group_store_->create_group(g);
                              if (!result) {
                                  res.set_content(
                                      "<span class=\"feedback-error\">" + result.error() + "</span>",
                                      "text/html; charset=utf-8");
                                  return;
                              }
                              if (audit_store_) {
                                  AuditEvent ae;
                                  ae.principal = session ? session->username : "unknown";
                                  ae.action = "management_group.create";
                                  ae.target_type = "ManagementGroup";
                                  ae.target_id = *result;
                                  ae.detail = name;
                                  ae.result = "success";
                                  audit_store_->log(ae);
                              }
                              res.set_content(render_management_groups_fragment(),
                                              "text/html; charset=utf-8");
                          });

        web_server_->Delete(
            R"(/api/settings/management-groups/([a-f0-9]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "ManagementGroup", "Delete"))
                    return;
                auto id = req.matches[1].str();
                auto result = mgmt_group_store_->delete_group(id);
                if (!result) {
                    res.set_content(
                        "<span class=\"feedback-error\">" + result.error() + "</span>",
                        "text/html; charset=utf-8");
                    return;
                }
                auto session = require_auth(req, res);
                if (audit_store_) {
                    AuditEvent ae;
                    ae.principal = session ? session->username : "unknown";
                    ae.action = "management_group.delete";
                    ae.target_type = "ManagementGroup";
                    ae.target_id = id;
                    ae.result = "success";
                    audit_store_->log(ae);
                }
                res.set_content(render_management_groups_fragment(), "text/html; charset=utf-8");
            });

        // -- Settings HTMX fragment: Tag Compliance / OTA Updates ----------------

        web_server_->Get("/fragments/settings/tag-compliance",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Tag", "Read"))
                                 return;
                             res.set_content(render_tag_compliance_fragment(),
                                             "text/html; charset=utf-8");
                         });

        web_server_->Get("/fragments/settings/updates",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_admin(req, res))
                                 return;
                             res.set_content(render_updates_fragment(), "text/html; charset=utf-8");
                         });

        // Upload new update package
        web_server_->Post("/api/settings/updates/upload", [this](const httplib::Request& req,
                                                                 httplib::Response& res) {
            if (!require_admin(req, res))
                return;
            if (!update_registry_) {
                res.status = 400;
                res.set_content("<span class=\"feedback-error\">OTA disabled.</span>",
                                "text/html; charset=utf-8");
                return;
            }

            std::string platform, arch, rollout_s, mandatory_s;
            if (req.form.has_field("platform"))
                platform = req.form.get_field("platform");
            if (req.form.has_field("arch"))
                arch = req.form.get_field("arch");
            if (req.form.has_field("rollout_pct"))
                rollout_s = req.form.get_field("rollout_pct");
            if (req.form.has_field("mandatory"))
                mandatory_s = req.form.get_field("mandatory");

            if (!req.form.has_file("file")) {
                res.status = 400;
                res.set_content("<span class=\"feedback-error\">No file uploaded.</span>",
                                "text/html; charset=utf-8");
                return;
            }
            const auto& uploaded = req.form.get_file("file");
            if (uploaded.content.empty()) {
                res.status = 400;
                res.set_content("<span class=\"feedback-error\">Empty file.</span>",
                                "text/html; charset=utf-8");
                return;
            }

            int rollout_pct = 100;
            try {
                if (!rollout_s.empty())
                    rollout_pct = std::stoi(rollout_s);
            } catch (...) {}
            if (rollout_pct < 0)
                rollout_pct = 0;
            if (rollout_pct > 100)
                rollout_pct = 100;

            // Derive version from filename (strip extension to use as version)
            auto orig_name = uploaded.filename.empty() ? "yuzu-agent-" + platform + "-" + arch
                                                       : uploaded.filename;

            // Use filename as-is for storage
            auto out_path =
                update_registry_->binary_path(UpdatePackage{platform, arch, "", "", orig_name});
            std::error_code ec;
            std::filesystem::create_directories(out_path.parent_path(), ec);
            {
                std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
                if (!f.is_open()) {
                    res.status = 500;
                    res.set_content("<span class=\"feedback-error\">Cannot write file.</span>",
                                    "text/html; charset=utf-8");
                    return;
                }
                f.write(uploaded.content.data(),
                        static_cast<std::streamsize>(uploaded.content.size()));
            }

            auto sha = auth::AuthManager::sha256_hex(uploaded.content);
            auto version = orig_name; // use filename as version identifier
            // Strip common extensions for a cleaner version string
            for (const auto* ext : {".exe", ".bin", ".tar.gz", ".zip", ".msi"}) {
                if (version.size() > std::strlen(ext) &&
                    version.substr(version.size() - std::strlen(ext)) == ext) {
                    version = version.substr(0, version.size() - std::strlen(ext));
                    break;
                }
            }

            UpdatePackage pkg;
            pkg.platform = platform;
            pkg.arch = arch;
            pkg.version = version;
            pkg.sha256 = sha;
            pkg.filename = orig_name;
            pkg.mandatory = (mandatory_s == "true");
            pkg.rollout_pct = rollout_pct;
            pkg.file_size = static_cast<int64_t>(uploaded.content.size());

            update_registry_->upsert_package(pkg);
            spdlog::info("OTA package uploaded: {}/{} v{} ({}B, rollout={}%)", platform, arch,
                         version, pkg.file_size, rollout_pct);

            res.set_content(render_updates_fragment(), "text/html; charset=utf-8");
        });

        // Delete an update package
        web_server_->Delete(
            R"(/api/settings/updates/([^/]+)/([^/]+)/([^/]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res))
                    return;
                if (!update_registry_) {
                    res.status = 400;
                    return;
                }

                auto platform = req.matches[1].str();
                auto arch = req.matches[2].str();
                auto version = req.matches[3].str();

                // Find the package to get filename for disk cleanup
                auto packages = update_registry_->list_packages();
                for (const auto& pkg : packages) {
                    if (pkg.platform == platform && pkg.arch == arch && pkg.version == version) {
                        auto bin_path = update_registry_->binary_path(pkg);
                        std::error_code ec;
                        std::filesystem::remove(bin_path, ec);
                        break;
                    }
                }

                update_registry_->remove_package(platform, arch, version);
                spdlog::info("OTA package deleted: {}/{} v{}", platform, arch, version);
                res.set_content(render_updates_fragment(), "text/html; charset=utf-8");
            });

        // Update rollout percentage
        web_server_->Post(
            R"(/api/settings/updates/([^/]+)/([^/]+)/([^/]+)/rollout)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res))
                    return;
                if (!update_registry_) {
                    res.status = 400;
                    return;
                }

                auto platform = req.matches[1].str();
                auto arch = req.matches[2].str();
                auto version = req.matches[3].str();
                auto pct_s = extract_form_value(req.body, "rollout_pct");

                int pct = 100;
                try {
                    if (!pct_s.empty())
                        pct = std::stoi(pct_s);
                } catch (...) {}
                if (pct < 0)
                    pct = 0;
                if (pct > 100)
                    pct = 100;

                // Find and update the package
                auto packages = update_registry_->list_packages();
                for (auto pkg : packages) {
                    if (pkg.platform == platform && pkg.arch == arch && pkg.version == version) {
                        pkg.rollout_pct = pct;
                        update_registry_->upsert_package(pkg);
                        spdlog::info("OTA rollout updated: {}/{} v{} → {}%", platform, arch,
                                     version, pct);
                        break;
                    }
                }

                res.set_content(render_updates_fragment(), "text/html; charset=utf-8");
            });

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
            res.set_content_provider(
                "text/event-stream",
                [sink_state](size_t offset, httplib::DataSink& sink) -> bool {
                    return detail::sse_content_provider(sink_state, offset, sink);
                },
                [sink_state, bus](bool success) {
                    detail::sse_resource_release(sink_state, *bus, success);
                });
        });

        // -- Agent listing API ------------------------------------------------

        web_server_->Get("/api/agents", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;

            auto session = require_auth(req, res);
            auto full_json = registry_.to_json();

            // If RBAC is enabled, filter to visible agents for non-global-admins
            if (rbac_store_ && rbac_store_->is_rbac_enabled() && mgmt_group_store_) {
                bool global_read =
                    rbac_store_->check_permission(session->username, "Infrastructure", "Read");
                if (!global_read) {
                    auto visible = mgmt_group_store_->get_visible_agents(session->username);
                    std::set<std::string> visible_set(visible.begin(), visible.end());
                    try {
                        auto arr = nlohmann::json::parse(full_json);
                        nlohmann::json filtered = nlohmann::json::array();
                        for (const auto& a : arr) {
                            if (a.contains("agent_id") &&
                                visible_set.count(a["agent_id"].get<std::string>()))
                                filtered.push_back(a);
                        }
                        res.set_content(filtered.dump(), "application/json");
                        return;
                    } catch (...) {
                        // Fall through to unfiltered
                    }
                }
            }

            res.set_content(full_json, "application/json");
        });

        web_server_->Get("/api/help", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;
            res.set_content(registry_.help_json(), "application/json");
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

        web_server_->Post(
            "/api/nvd/sync", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Infrastructure", "Execute"))
                    return;
                if (!nvd_sync_) {
                    res.status = 503;
                    res.set_content(R"({"error":"NVD sync not enabled"})", "application/json");
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
                res.set_content(R"({"error":"NVD database not available"})", "application/json");
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
                res.set_content(R"({"error":"invalid JSON body"})", "application/json");
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
                res.set_content("{\"error\":\"plugin and action are required\"}",
                                "application/json");
                return;
            }

            // All commands require Execution:Execute permission
            if (!require_permission(req, res, "Execution", "Execute"))
                return;

            if (!registry_.has_any()) {
                res.status = 503;
                res.set_content("{\"error\":\"no agent connected\"}", "application/json");
                return;
            }

            auto command_id =
                plugin + "-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));

            detail::pb::CommandRequest cmd;
            cmd.set_command_id(command_id);
            cmd.set_plugin(plugin);
            cmd.set_action(action);

            // Stagger/delay: prevent thundering herd on large-fleet dispatch
            auto stagger = extract_json_int(req.body, "stagger", 0);
            auto delay = extract_json_int(req.body, "delay", 0);
            if (stagger > 0) cmd.set_stagger_seconds(stagger);
            if (delay > 0) cmd.set_delay_seconds(delay);

            agent_service_.record_send_time(command_id);

            // Check for scope-based targeting
            auto scope_expr = extract_json_string(req.body, "scope");

            int sent = 0;
            if (!scope_expr.empty()) {
                // Scope-based dispatch
                auto parsed = yuzu::scope::parse(scope_expr);
                if (!parsed) {
                    res.status = 400;
                    res.set_content(
                        nlohmann::json({{"error", "invalid scope: " + parsed.error()}}).dump(),
                        "application/json");
                    return;
                }
                auto matched_ids = registry_.evaluate_scope(*parsed, tag_store_.get());
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

            if (sent == 0) {
                res.status = 503;
                res.set_content("{\"error\":\"failed to send command to any agent\"}",
                                "application/json");
                return;
            }

            metrics_.counter("yuzu_commands_dispatched_total").increment();
            spdlog::info("Command dispatched: {}:{} → {} agent(s)", plugin, action, sent);
            audit_log(req, "command.dispatch", "success", "command", command_id,
                      plugin + ":" + action + " → " + std::to_string(sent) + " agent(s)");
            emit_event("command.dispatched", req, {{"target_count", sent}},
                       {{"plugin", plugin},
                        {"action", action},
                        {"command_id", command_id},
                        {"scope", scope_expr}});
            res.set_header("HX-Trigger",
                "{\"showToast\":{\"message\":\"Command sent to " + std::to_string(sent) +
                " agent(s)\",\"level\":\"success\"}}");
            res.set_content(
                nlohmann::json(
                    {{"status", "sent"}, {"command_id", command_id}, {"agents_reached", sent}})
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
                res.set_content(R"({"error":"response store not available"})", "application/json");
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
            if (req.has_param("status"))
                filter.status = std::stoi(req.get_param_value("status"));
            if (req.has_param("since"))
                filter.since = std::stoll(req.get_param_value("since"));
            if (req.has_param("until"))
                filter.until = std::stoll(req.get_param_value("until"));

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
                res.set_content(R"({"error":"response store not available"})", "application/json");
                return;
            }

            ResponseQuery q;
            if (req.has_param("agent_id"))
                q.agent_id = req.get_param_value("agent_id");
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
                res.set_content(R"({"error":"instruction_id required"})", "application/json");
                return;
            }

            if (!response_store_ || !response_store_->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":"response store not available"})", "application/json");
                return;
            }

            ResponseQuery q;
            if (req.has_param("agent_id"))
                q.agent_id = req.get_param_value("agent_id");
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
                res.set_content(R"({"error":"audit store not available"})", "application/json");
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
            if (req.has_param("since"))
                q.since = std::stoll(req.get_param_value("since"));
            if (req.has_param("until"))
                q.until = std::stoll(req.get_param_value("until"));
            if (req.has_param("limit"))
                q.limit = std::stoi(req.get_param_value("limit"));
            if (req.has_param("offset"))
                q.offset = std::stoi(req.get_param_value("offset"));

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
                res.set_content(R"({"error":"tag store not available"})", "application/json");
                return;
            }

            auto agent_id = req.get_param_value("agent_id");
            if (agent_id.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"agent_id parameter required"})", "application/json");
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

        web_server_->Post(
            "/api/tags/set", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Tag", "Write"))
                    return;
                if (!tag_store_) {
                    res.status = 503;
                    res.set_content(R"({"error":"tag store not available"})", "application/json");
                    return;
                }

                auto agent_id = extract_json_string(req.body, "agent_id");
                auto key = extract_json_string(req.body, "key");
                auto value = extract_json_string(req.body, "value");

                if (agent_id.empty() || key.empty()) {
                    res.status = 400;
                    res.set_content(R"({"error":"agent_id and key required"})", "application/json");
                    return;
                }

                if (!TagStore::validate_key(key)) {
                    res.status = 400;
                    res.set_content(R"({"error":"invalid tag key"})", "application/json");
                    return;
                }

                tag_store_->set_tag(agent_id, key, value, "api");
                if (key == "service")
                    ensure_service_management_group(value);
                // Push updated tags to agent if a structured category changed
                for (auto cat_key : kCategoryKeys) {
                    if (cat_key == key) {
                        push_asset_tags_to_agent(agent_id);
                        break;
                    }
                }
                audit_log(req, "tag.set", "success", "tag", agent_id + ":" + key, value);
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"Tag updated","level":"success"}})");
                res.set_content(R"({"status":"ok"})", "application/json");
            });

        web_server_->Post(
            "/api/tags/delete", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Tag", "Delete"))
                    return;
                if (!tag_store_) {
                    res.status = 503;
                    res.set_content(R"({"error":"tag store not available"})", "application/json");
                    return;
                }

                auto agent_id = extract_json_string(req.body, "agent_id");
                auto key = extract_json_string(req.body, "key");

                if (agent_id.empty() || key.empty()) {
                    res.status = 400;
                    res.set_content(R"({"error":"agent_id and key required"})", "application/json");
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

        web_server_->Post(
            "/api/tags/query", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Tag", "Read"))
                    return;
                if (!tag_store_) {
                    res.status = 503;
                    res.set_content(R"({"error":"tag store not available"})", "application/json");
                    return;
                }

                auto key = extract_json_string(req.body, "key");
                auto value = extract_json_string(req.body, "value");

                if (key.empty()) {
                    res.status = 400;
                    res.set_content(R"({"error":"key required"})", "application/json");
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

        // -- Compliance dashboard page ----------------------------------------
        web_server_->Get("/compliance",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             auto session = require_auth(req, res);
                             if (!session) {
                                 res.set_redirect("/login");
                                 return;
                             }
                             res.set_content(kComplianceHtml, "text/html; charset=utf-8");
                         });

        // -- Compliance HTMX fragment: fleet summary --------------------------
        web_server_->Get("/fragments/compliance/summary",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             auto session = require_auth(req, res);
                             if (!session) return;
                             res.set_content(render_compliance_summary_fragment(),
                                             "text/html; charset=utf-8");
                         });

        // -- Compliance HTMX fragment: per-policy agent detail ----------------
        web_server_->Get(R"(/fragments/compliance/(\w[\w\-]*))",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             auto session = require_auth(req, res);
                             if (!session) return;
                             auto policy_id = req.matches[1].str();
                             res.set_content(render_compliance_detail_fragment(policy_id),
                                             "text/html; charset=utf-8");
                         });

        // -- Generic JSON-to-CSV export -----------------------------------------
        web_server_->Post(
            "/api/export/json-to-csv", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Response", "Read"))
                    return;

                auto csv = data_export::json_array_to_csv(req.body);
                if (csv.empty()) {
                    res.status = 400;
                    res.set_content(R"({"error":"invalid JSON array"})", "application/json");
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
                res.set_content(R"({"error":"instruction store not available"})",
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
            if (req.has_param("limit"))
                q.limit = std::stoi(req.get_param_value("limit"));

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
                return;
            }

            try {
                auto j = nlohmann::json::parse(req.body);
                InstructionDefinition def;
                def.name = j.value("name", "");
                def.version = j.value("version", "1.0");
                def.type = j.value("type", "");
                def.plugin = j.value("plugin", "");
                def.action = j.value("action", "");
                def.description = j.value("description", "");
                def.enabled = j.value("enabled", true);
                def.instruction_set_id = j.value("instruction_set_id", "");
                def.gather_ttl_seconds = j.value("gather_ttl_seconds", 300);
                def.response_ttl_days = j.value("response_ttl_days", 90);

                auto token = extract_session_cookie(req);
                auto session = auth_mgr_.validate_session(token);
                if (session)
                    def.created_by = session->username;

                auto result = instruction_store_->create_definition(def);
                if (!result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
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
                res.set_header("HX-Trigger",
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
                return;
            }

            auto id = req.matches[1].str();
            auto def = instruction_store_->get_definition(id);
            if (!def) {
                res.status = 404;
                res.set_content(R"({"error":"not found"})", "application/json");
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
                return;
            }

            auto id = req.matches[1].str();
            try {
                auto j = nlohmann::json::parse(req.body);
                InstructionDefinition def;
                def.id = id;
                def.name = j.value("name", "");
                def.version = j.value("version", "1.0");
                def.type = j.value("type", "");
                def.plugin = j.value("plugin", "");
                def.action = j.value("action", "");
                def.description = j.value("description", "");
                def.enabled = j.value("enabled", true);
                def.instruction_set_id = j.value("instruction_set_id", "");

                auto result = instruction_store_->update_definition(def);
                if (!result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                    "application/json");
                    return;
                }
                audit_log(req, "instruction.update", "success", "instruction", id);
                emit_event("instruction.updated", req, {}, {{"instruction_id", id}});
                res.set_header("HX-Trigger",
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
                return;
            }

            auto id = req.matches[1].str();
            bool deleted = instruction_store_->delete_definition(id);
            if (deleted) {
                audit_log(req, "instruction.delete", "success", "instruction", id);
                emit_event("instruction.deleted", req, {}, {{"instruction_id", id}});
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"Instruction definition deleted","level":"success"}})");
            }
            res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
        });

        web_server_->Get(R"(/api/instructions/([^/]+)/export)",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "InstructionDefinition", "Read"))
                                 return;
                             if (!instruction_store_) {
                                 res.status = 503;
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
                return;
            }

            auto result = instruction_store_->import_definition_json(req.body);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(),
                                "application/json");
                return;
            }
            audit_log(req, "instruction.import", "success", "instruction", *result);
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Definitions imported","level":"success"}})");
            res.set_content(nlohmann::json({{"id", *result}}).dump(), "application/json");
        });

        // -- Instruction Sets API ---------------------------------------------

        web_server_->Get(
            "/api/instruction-sets", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "InstructionSet", "Read"))
                    return;
                if (!instruction_store_) {
                    res.status = 503;
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

        web_server_->Post(
            "/api/instruction-sets", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "InstructionSet", "Write"))
                    return;
                if (!instruction_store_) {
                    res.status = 503;
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
                return;
            }

            auto id = req.matches[1].str();
            bool deleted = instruction_store_->delete_set(id);
            res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
        });

        // -- Execution API ----------------------------------------------------

        web_server_->Get(
            "/api/executions", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Execution", "Read"))
                    return;
                if (!execution_tracker_) {
                    res.status = 503;
                    return;
                }

                ExecutionQuery q;
                if (req.has_param("definition_id"))
                    q.definition_id = req.get_param_value("definition_id");
                if (req.has_param("status"))
                    q.status = req.get_param_value("status");
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));

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
                return;
            }

            auto id = req.matches[1].str();
            auto exec = execution_tracker_->get_execution(id);
            if (!exec) {
                res.status = 404;
                res.set_content(R"({"error":"not found"})", "application/json");
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
                return;
            }

            auto id = req.matches[1].str();
            auto scope_filter = extract_json_string(req.body, "scope");
            bool failed_only = (scope_filter == "failed_only");

            auto token = extract_session_cookie(req);
            auto session = auth_mgr_.validate_session(token);
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
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Execution rerun initiated","level":"success"}})");
            res.set_content(nlohmann::json({{"id", *result}}).dump(), "application/json");
        });

        web_server_->Post(R"(/api/executions/([^/]+)/cancel)",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_permission(req, res, "Execution", "Execute"))
                                  return;
                              if (!execution_tracker_) {
                                  res.status = 503;
                                  return;
                              }

                              auto id = req.matches[1].str();
                              auto token = extract_session_cookie(req);
                              auto session = auth_mgr_.validate_session(token);
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

        web_server_->Get(
            "/api/schedules", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Schedule", "Read"))
                    return;
                if (!schedule_engine_) {
                    res.status = 503;
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

                auto token = extract_session_cookie(req);
                auto session = auth_mgr_.validate_session(token);
                if (session)
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
                return;
            }

            auto id = req.matches[1].str();
            auto enabled_str = extract_json_string(req.body, "enabled");
            bool enabled = (enabled_str != "false");
            schedule_engine_->set_enabled(id, enabled);
            res.set_content(nlohmann::json({{"enabled", enabled}}).dump(), "application/json");
        });

        // -- Approval API -----------------------------------------------------

        web_server_->Get(
            "/api/approvals", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Approval", "Read"))
                    return;
                if (!approval_manager_) {
                    res.status = 503;
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
                return;
            }

            auto id = req.matches[1].str();
            auto comment = extract_json_string(req.body, "comment");
            auto token = extract_session_cookie(req);
            auto session = auth_mgr_.validate_session(token);
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
                return;
            }

            auto id = req.matches[1].str();
            auto comment = extract_json_string(req.body, "comment");
            auto token = extract_session_cookie(req);
            auto session = auth_mgr_.validate_session(token);
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
        web_server_->Post(
            "/api/instructions/yaml", [this](const httplib::Request& req, httplib::Response& res) {
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
                def.type = extract("type");
                def.description = extract("description");
                def.concurrency_mode = extract("concurrency");
                def.approval_mode = extract("approval");
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
                    html +=
                        R"(<div id="yaml-errors" hx-swap-oob="innerHTML:#yaml-errors"></div>)";
                }
                res.set_content(html, "text/html");
            });

        web_server_->Get("/fragments/executions", [this](const httplib::Request& req,
                                                         httplib::Response& res) {
            auto session = require_auth(req, res);
            if (!session)
                return;
            if (!execution_tracker_) {
                res.set_content("<div class=\"empty-state\">Not available</div>", "text/html");
                return;
            }

            ExecutionQuery q;
            q.limit = 50;
            auto execs = execution_tracker_->query_executions(q);
            std::string html;
            if (execs.empty()) {
                html = "<div class=\"empty-state\">No executions yet.</div>";
            } else {
                html = "<table><thead><tr><th>ID</th><th>Status</th><th>Progress</"
                       "th><th>Dispatched By</th><th>Time</th></tr></thead><tbody>";
                for (const auto& e : execs) {
                    auto pct =
                        e.agents_targeted > 0 ? (e.agents_responded * 100 / e.agents_targeted) : 0;
                    auto status_cls = "status-" + e.status;
                    html += "<tr><td><code style=\"font-size:0.7rem\">" +
                            html_escape(e.id.substr(0, 12)) +
                            "</code></td>"
                            "<td><span class=\"status-badge " +
                            status_cls + "\">" + html_escape(e.status) +
                            "</span></td>"
                            "<td><div class=\"progress-bar\"><div class=\"progress-fill\" "
                            "style=\"width:" +
                            std::to_string(pct) +
                            "%\"></div></div>"
                            "<span style=\"font-size:0.65rem\">" +
                            std::to_string(e.agents_responded) + "/" +
                            std::to_string(e.agents_targeted) +
                            "</span></td>"
                            "<td>" +
                            html_escape(e.dispatched_by) +
                            "</td>"
                            "<td style=\"font-size:0.7rem\">" +
                            std::to_string(e.dispatched_at) + "</td></tr>";
                }
                html += "</tbody></table>";
            }
            res.set_content(html, "text/html; charset=utf-8");
        });

        web_server_->Get("/fragments/schedules", [this](const httplib::Request& req,
                                                        httplib::Response& res) {
            auto session = require_auth(req, res);
            if (!session)
                return;
            if (!schedule_engine_) {
                res.set_content("<div class=\"empty-state\">Not available</div>", "text/html");
                return;
            }

            auto scheds = schedule_engine_->query_schedules();
            std::string html;
            if (scheds.empty()) {
                html = "<div class=\"empty-state\">No schedules configured.</div>";
            } else {
                html = "<table><thead><tr><th>Name</th><th>Frequency</th><th>Enabled</th><th>Next "
                       "Run</th><th>Count</th><th></th></tr></thead><tbody>";
                for (const auto& s : scheds) {
                    html += "<tr><td>" + html_escape(s.name) +
                            "</td>"
                            "<td><code>" +
                            html_escape(s.frequency_type) +
                            "</code></td>"
                            "<td>" +
                            std::string(s.enabled ? "Yes" : "No") +
                            "</td>"
                            "<td style=\"font-size:0.7rem\">" +
                            (s.next_execution_at > 0 ? std::to_string(s.next_execution_at) : "-") +
                            "</td>"
                            "<td>" +
                            std::to_string(s.execution_count) +
                            "</td>"
                            "<td><button class=\"btn btn-danger\" "
                            "style=\"font-size:0.65rem;padding:0.15rem 0.5rem\" "
                            "hx-delete=\"/api/schedules/" +
                            s.id +
                            "\" hx-target=\"#tab-schedules\" hx-swap=\"innerHTML\" "
                            "hx-confirm=\"Delete schedule?\">Delete</button></td></tr>";
                }
                html += "</tbody></table>";
            }
            res.set_content(html, "text/html; charset=utf-8");
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
        web_server_->Post(
            "/api/scope/validate", [this](const httplib::Request& req, httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session)
                    return;

                auto expression = extract_json_string(req.body, "expression");
                if (expression.empty()) {
                    res.status = 400;
                    res.set_content(R"({"error":"expression required"})", "application/json");
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

        web_server_->Post("/api/scope/estimate", [this](const httplib::Request& req,
                                                        httplib::Response& res) {
            auto session = require_auth(req, res);
            if (!session)
                return;

            auto expression = extract_json_string(req.body, "expression");
            if (expression.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"expression required"})", "application/json");
                return;
            }

            auto parsed = yuzu::scope::parse(expression);
            if (!parsed) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", parsed.error()}}).dump(),
                                "application/json");
                return;
            }

            auto matched = registry_.evaluate_scope(*parsed, tag_store_.get());
            res.set_content(
                nlohmann::json({{"matched", matched.size()}, {"total", registry_.agent_count()}})
                    .dump(),
                "application/json");
        });

        // -- Policy Engine API (Phase 5) ------------------------------------------

        // GET /api/policy-fragments — list all fragments
        web_server_->Get("/api/policy-fragments",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Read"))
                    return;
                if (!policy_store_ || !policy_store_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":"policy store not available"})", "application/json");
                    return;
                }

                FragmentQuery q;
                if (req.has_param("name"))
                    q.name_filter = req.get_param_value("name");
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));

                auto frags = policy_store_->query_fragments(q);
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& f : frags) {
                    arr.push_back({{"id", f.id},
                                   {"name", f.name},
                                   {"description", f.description},
                                   {"check_instruction", f.check_instruction},
                                   {"check_compliance", f.check_compliance},
                                   {"fix_instruction", f.fix_instruction},
                                   {"post_check_instruction", f.post_check_instruction},
                                   {"created_at", f.created_at},
                                   {"updated_at", f.updated_at}});
                }
                res.set_content(
                    nlohmann::json({{"fragments", arr}, {"count", arr.size()}}).dump(),
                    "application/json");
            });

        // POST /api/policy-fragments — create fragment from YAML
        web_server_->Post("/api/policy-fragments",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Write"))
                    return;
                if (!policy_store_ || !policy_store_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":"policy store not available"})", "application/json");
                    return;
                }

                std::string yaml_source;
                // Accept raw YAML body or JSON with yaml_source field
                if (req.get_header_value("Content-Type").find("application/json") != std::string::npos) {
                    try {
                        auto j = nlohmann::json::parse(req.body);
                        yaml_source = j.value("yaml_source", "");
                    } catch (const std::exception& e) {
                        res.status = 400;
                        res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                        return;
                    }
                } else {
                    yaml_source = req.body;
                }

                auto result = policy_store_->create_fragment(yaml_source);
                if (!result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                    return;
                }
                audit_log(req, "policy_fragment.create", "success", "policy_fragment", *result);
                emit_event("policy_fragment.created", req, {}, {{"fragment_id", *result}});
                res.status = 201;
                res.set_content(nlohmann::json({{"id", *result}, {"status", "created"}}).dump(),
                                "application/json");
            });

        // DELETE /api/policy-fragments/:id
        web_server_->Delete(R"(/api/policy-fragments/([^/]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Delete"))
                    return;
                if (!policy_store_) {
                    res.status = 503;
                    return;
                }

                auto id = req.matches[1].str();
                bool deleted = policy_store_->delete_fragment(id);
                if (deleted) {
                    audit_log(req, "policy_fragment.delete", "success", "policy_fragment", id);
                    emit_event("policy_fragment.deleted", req, {}, {{"fragment_id", id}});
                }
                res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
            });

        // GET /api/policies — list all policies
        web_server_->Get("/api/policies",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Read"))
                    return;
                if (!policy_store_ || !policy_store_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":"policy store not available"})", "application/json");
                    return;
                }

                PolicyQuery q;
                if (req.has_param("name"))
                    q.name_filter = req.get_param_value("name");
                if (req.has_param("fragment_id"))
                    q.fragment_filter = req.get_param_value("fragment_id");
                if (req.has_param("enabled_only"))
                    q.enabled_only = true;
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));

                auto policies = policy_store_->query_policies(q);
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& p : policies) {
                    nlohmann::json inputs_obj = nlohmann::json::object();
                    for (const auto& inp : p.inputs)
                        inputs_obj[inp.key] = inp.value;

                    nlohmann::json triggers_arr = nlohmann::json::array();
                    for (const auto& t : p.triggers) {
                        triggers_arr.push_back({{"id", t.id},
                                                {"type", t.trigger_type},
                                                {"config", nlohmann::json::parse(t.config_json, nullptr, false)}});
                    }

                    arr.push_back({{"id", p.id},
                                   {"name", p.name},
                                   {"description", p.description},
                                   {"fragment_id", p.fragment_id},
                                   {"scope_expression", p.scope_expression},
                                   {"enabled", p.enabled},
                                   {"inputs", inputs_obj},
                                   {"triggers", triggers_arr},
                                   {"management_groups", p.management_groups},
                                   {"created_at", p.created_at},
                                   {"updated_at", p.updated_at}});
                }
                res.set_content(
                    nlohmann::json({{"policies", arr}, {"count", arr.size()}}).dump(),
                    "application/json");
            });

        // POST /api/policies — create policy from YAML
        web_server_->Post("/api/policies",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Write"))
                    return;
                if (!policy_store_ || !policy_store_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":"policy store not available"})", "application/json");
                    return;
                }

                std::string yaml_source;
                if (req.get_header_value("Content-Type").find("application/json") != std::string::npos) {
                    try {
                        auto j = nlohmann::json::parse(req.body);
                        yaml_source = j.value("yaml_source", "");
                    } catch (const std::exception& e) {
                        res.status = 400;
                        res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                        return;
                    }
                } else {
                    yaml_source = req.body;
                }

                auto result = policy_store_->create_policy(yaml_source);
                if (!result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                    return;
                }
                audit_log(req, "policy.create", "success", "policy", *result);
                emit_event("policy.created", req, {}, {{"policy_id", *result}});
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"Policy created","level":"success"}})");
                res.status = 201;
                res.set_content(nlohmann::json({{"id", *result}, {"status", "created"}}).dump(),
                                "application/json");
            });

        // GET /api/policies/:id — get policy detail
        web_server_->Get(R"(/api/policies/([^/]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Read"))
                    return;
                if (!policy_store_) {
                    res.status = 503;
                    return;
                }

                auto id = req.matches[1].str();
                auto policy = policy_store_->get_policy(id);
                if (!policy) {
                    res.status = 404;
                    res.set_content(R"({"error":"policy not found"})", "application/json");
                    return;
                }

                nlohmann::json inputs_obj = nlohmann::json::object();
                for (const auto& inp : policy->inputs)
                    inputs_obj[inp.key] = inp.value;

                nlohmann::json triggers_arr = nlohmann::json::array();
                for (const auto& t : policy->triggers) {
                    triggers_arr.push_back({{"id", t.id},
                                            {"type", t.trigger_type},
                                            {"config", nlohmann::json::parse(t.config_json, nullptr, false)}});
                }

                // Also fetch compliance summary
                auto cs = policy_store_->get_compliance_summary(id);

                res.set_content(
                    nlohmann::json({{"id", policy->id},
                                    {"name", policy->name},
                                    {"description", policy->description},
                                    {"yaml_source", policy->yaml_source},
                                    {"fragment_id", policy->fragment_id},
                                    {"scope_expression", policy->scope_expression},
                                    {"enabled", policy->enabled},
                                    {"inputs", inputs_obj},
                                    {"triggers", triggers_arr},
                                    {"management_groups", policy->management_groups},
                                    {"created_at", policy->created_at},
                                    {"updated_at", policy->updated_at},
                                    {"compliance", {{"compliant", cs.compliant},
                                                     {"non_compliant", cs.non_compliant},
                                                     {"unknown", cs.unknown},
                                                     {"fixing", cs.fixing},
                                                     {"error", cs.error},
                                                     {"total", cs.total}}}})
                        .dump(),
                    "application/json");
            });

        // DELETE /api/policies/:id
        web_server_->Delete(R"(/api/policies/([^/]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Delete"))
                    return;
                if (!policy_store_) {
                    res.status = 503;
                    return;
                }

                auto id = req.matches[1].str();
                bool deleted = policy_store_->delete_policy(id);
                if (deleted) {
                    audit_log(req, "policy.delete", "success", "policy", id);
                    emit_event("policy.deleted", req, {}, {{"policy_id", id}});
                    res.set_header("HX-Trigger",
                        R"({"showToast":{"message":"Policy deleted","level":"success"}})");
                }
                res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
            });

        // POST /api/policies/:id/enable
        web_server_->Post(R"(/api/policies/([^/]+)/enable)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Write"))
                    return;
                if (!policy_store_) {
                    res.status = 503;
                    return;
                }

                auto id = req.matches[1].str();
                auto result = policy_store_->enable_policy(id);
                if (!result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                    return;
                }
                audit_log(req, "policy.enable", "success", "policy", id);
                emit_event("policy.enabled", req, {}, {{"policy_id", id}});
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"Policy enabled","level":"success"}})");
                res.set_content(R"({"status":"ok"})", "application/json");
            });

        // POST /api/policies/:id/disable
        web_server_->Post(R"(/api/policies/([^/]+)/disable)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Write"))
                    return;
                if (!policy_store_) {
                    res.status = 503;
                    return;
                }

                auto id = req.matches[1].str();
                auto result = policy_store_->disable_policy(id);
                if (!result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                    return;
                }
                audit_log(req, "policy.disable", "success", "policy", id);
                emit_event("policy.disabled", req, {}, {{"policy_id", id}});
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"Policy disabled","level":"warning"}})");
                res.set_content(R"({"status":"ok"})", "application/json");
            });

        // GET /api/compliance — fleet compliance summary
        web_server_->Get("/api/compliance",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Read"))
                    return;
                if (!policy_store_) {
                    res.status = 503;
                    return;
                }

                auto fc = policy_store_->get_fleet_compliance();
                res.set_content(
                    nlohmann::json({{"compliance_pct", fc.compliance_pct},
                                    {"total_checks", fc.total_checks},
                                    {"compliant", fc.compliant},
                                    {"non_compliant", fc.non_compliant},
                                    {"unknown", fc.unknown},
                                    {"fixing", fc.fixing},
                                    {"error", fc.error}})
                        .dump(),
                    "application/json");
            });

        // GET /api/compliance/:policy_id — per-policy compliance detail
        web_server_->Get(R"(/api/compliance/([^/]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Read"))
                    return;
                if (!policy_store_) {
                    res.status = 503;
                    return;
                }

                auto policy_id = req.matches[1].str();
                auto summary = policy_store_->get_compliance_summary(policy_id);
                auto statuses = policy_store_->get_policy_agent_statuses(policy_id);

                nlohmann::json agents_arr = nlohmann::json::array();
                for (const auto& s : statuses) {
                    agents_arr.push_back({{"agent_id", s.agent_id},
                                          {"status", s.status},
                                          {"last_check_at", s.last_check_at},
                                          {"last_fix_at", s.last_fix_at},
                                          {"check_result", s.check_result}});
                }

                res.set_content(
                    nlohmann::json({{"policy_id", policy_id},
                                    {"summary", {{"compliant", summary.compliant},
                                                  {"non_compliant", summary.non_compliant},
                                                  {"unknown", summary.unknown},
                                                  {"fixing", summary.fixing},
                                                  {"error", summary.error},
                                                  {"total", summary.total}}},
                                    {"agents", agents_arr}})
                        .dump(),
                    "application/json");
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
                for (auto cat_key : kCategoryKeys) {
                    if (cat_key == key) {
                        push_asset_tags_to_agent(agent_id);
                        break;
                    }
                }
            });

        // -- Listen -----------------------------------------------------------

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
            res.set_content("{\"error\":\"no agent connected\"}", "application/json");
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
            res.set_content("{\"error\":\"failed to send command\"}", "application/json");
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
    std::shared_ptr<spdlog::logger> file_logger_;
    std::unique_ptr<grpc::Server> agent_server_;
    std::unique_ptr<grpc::Server> mgmt_server_;
    std::unique_ptr<httplib::Server> web_server_;
    std::thread web_thread_;

    // HTTPS redirect server
    std::unique_ptr<httplib::Server> redirect_server_;
    std::thread redirect_thread_;

    // OIDC SSO
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
    std::unique_ptr<ExecutionTracker> execution_tracker_;
    std::unique_ptr<ApprovalManager> approval_manager_;
    std::unique_ptr<ScheduleEngine> schedule_engine_;
    sqlite3* shared_instr_db_{nullptr};

    // Phase 3: Security & RBAC
    std::unique_ptr<RbacStore> rbac_store_;
    std::unique_ptr<ManagementGroupStore> mgmt_group_store_;
    std::unique_ptr<ApiTokenStore> api_token_store_;
    std::unique_ptr<QuarantineStore> quarantine_store_;
    std::unique_ptr<PolicyStore> policy_store_;
    std::unique_ptr<RestApiV1> rest_api_v1_;

    // Fleet health aggregation
    detail::AgentHealthStore health_store_;
    std::thread health_recompute_thread_;
    std::atomic<bool> stop_requested_{false};
};

// -- Factory ------------------------------------------------------------------

std::unique_ptr<Server> Server::create(Config config, auth::AuthManager& auth_mgr) {
    return std::make_unique<ServerImpl>(std::move(config), auth_mgr);
}

} // namespace yuzu::server
