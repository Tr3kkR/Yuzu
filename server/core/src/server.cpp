// M14/L15: This file (server.cpp) is ~8,800+ lines and due for decomposition.
// Planned extraction into separate translation units:
//   - settings_routes.cpp   — Settings page HTMX routes (TLS, users, enrollment, AD)
//   - compliance_routes.cpp — Compliance dashboard routes and policy evaluation
//   - auth_routes.cpp       — Login, logout, OIDC, session management routes
//   - webhook_routes.cpp    — Webhook CRUD and delivery routes
//   - workflow_routes.cpp   — Workflow engine routes and execution tracking
//   - notification_routes.cpp — Notification CRUD and bell icon routes
//   - discovery_routes.cpp  — Device discovery scan and result routes
// Each extraction should move the route registration lambdas and any
// helper functions they closure-capture. The Server class itself stays here
// as the composition root.

#include <yuzu/metrics.hpp>
#include <yuzu/secure_zero.hpp>
#include "cert_reloader.hpp"
#include "file_utils.hpp"
#include "web_utils.hpp"
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/server/server.hpp>

#include "agent.grpc.pb.h"
#include "analytics_event.hpp"
#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "compliance_eval.hpp"
#include "custom_properties_store.hpp"
#include "data_export.hpp"
#include "deployment_store.hpp"
#include "device_token_store.hpp"
#include "discovery_store.hpp"
#include "execution_tracker.hpp"
#include "gateway.grpc.pb.h"
#include "instruction_store.hpp"
#include "inventory_store.hpp"
#include "license_store.hpp"
#include "management.grpc.pb.h"
#include "management_group_store.hpp"
#include "notification_store.hpp"
#include "nvd_db.hpp"
#include "policy_store.hpp"
#include "product_pack_store.hpp"
#include "nvd_sync.hpp"
#include "oidc_provider.hpp"
#include "quarantine_store.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "mcp_jsonrpc.hpp"
#include "mcp_server.hpp"
#include "rest_api_v1.hpp"
#include "runtime_config_store.hpp"
#include "schedule_engine.hpp"
#include "scope_engine.hpp"
#include "software_deployment_store.hpp"
#include "tag_store.hpp"
#include "update_registry.hpp"
#include "webhook_store.hpp"
#include "workflow_engine.hpp"
#include "directory_sync.hpp"
#include "patch_manager.hpp"
#include "process_health.hpp"
#include "rate_limiter.hpp"

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
    template<typename T, typename = void>
    struct has_form_member : std::false_type {};
    template<typename T>
    struct has_form_member<T, std::void_t<decltype(std::declval<T>().form)>> : std::true_type {};
  }
  template<typename Req>
  bool yuzu_req_has_file(const Req& req, const std::string& name) {
      if constexpr (yuzu::detail::has_form_member<Req>::value)
          return req.form.has_file(name);
      else
          return req.has_file(name);
  }
  template<typename Req>
  auto yuzu_req_get_file(const Req& req, const std::string& name) {
      if constexpr (yuzu::detail::has_form_member<Req>::value)
          return req.form.get_file(name);
      else
          return req.get_file_value(name);
  }
  #define YUZU_REQ_HAS_FILE(req, name)  yuzu_req_has_file(req, name)
  #define YUZU_REQ_GET_FILE(req, name)  yuzu_req_get_file(req, name)
#endif

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

    std::size_t listener_count() const {
        std::lock_guard<std::mutex> lock(mu_);
        return listeners_.size();
    }

private:
    mutable std::mutex mu_;
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
    std::string gateway_node;  // Non-empty if agent is connected via gateway

    // Stream pointer — valid only while Subscribe() RPC is active.
    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream = nullptr;
    grpc::ServerContext* server_context = nullptr; // for timeout cancellation
    std::mutex stream_mu;

    // Last activity timestamp — updated on Subscribe reads and Heartbeats.
    // Atomic to avoid acquiring the registry mutex on every stream Read.
    std::atomic<int64_t> last_activity_epoch_ms{
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()};
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
                    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream,
                    grpc::ServerContext* context = nullptr) {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it != agents_.end()) {
            std::lock_guard slock(it->second->stream_mu);
            it->second->stream = stream;
            it->second->server_context = context;
            it->second->last_activity_epoch_ms.store(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count(),
                std::memory_order_relaxed);
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
            session->server_context = nullptr;
        }
    }

    /// Update last_activity timestamp for an agent (called on heartbeat + subscribe reads).
    /// Lock-free: last_activity_epoch_ms is atomic, so no mutex needed.
    void touch_activity(const std::string& agent_id) {
        std::shared_ptr<AgentSession> session;
        {
            std::lock_guard lock(mu_);
            auto it = agents_.find(agent_id);
            if (it == agents_.end()) return;
            session = it->second;
        }
        session->last_activity_epoch_ms.store(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count(),
            std::memory_order_relaxed);
    }

    /// Cancel Subscribe streams for agents that haven't heartbeated within the timeout.
    void reap_stale_sessions(std::chrono::seconds timeout) {
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now().time_since_epoch()).count();
        auto timeout_ms = std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count();

        // Collect shared_ptrs (not raw pointers) to keep sessions alive during TryCancel.
        std::vector<std::pair<std::string, std::shared_ptr<AgentSession>>> stale;
        {
            std::lock_guard lock(mu_);
            for (auto& [id, session] : agents_) {
                auto last = session->last_activity_epoch_ms.load(std::memory_order_relaxed);
                if ((now_ms - last) > timeout_ms) {
                    stale.emplace_back(id, session);
                }
            }
        }

        for (auto& [id, session] : stale) {
            // Acquire stream_mu and re-check context is still valid before cancelling.
            std::lock_guard slock(session->stream_mu);
            if (session->server_context) {
                spdlog::warn("Session timeout: cancelling Subscribe stream for agent {} "
                             "(no activity for >{}s)", id, timeout.count());
                session->server_context->TryCancel();
            }
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

    void set_gateway_node(const std::string& agent_id, const std::string& node) {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it != agents_.end()) {
            it->second->gateway_node = node;
        }
    }

    // Send a command to a specific agent. Returns false if agent not found or write failed.
    // For gateway agents (no local stream), adds to gateway_pending and returns true.
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
        if (session->stream)
            return session->stream->Write(cmd, grpc::WriteOptions());
        // Gateway agent — no local stream but agent is registered
        if (!session->gateway_node.empty()) {
            std::lock_guard glock(gw_pending_mu_);
            gw_pending_.push_back({agent_id, cmd});
            return true;
        }
        return false;
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
            } else if (!s->gateway_node.empty()) {
                std::lock_guard glock(gw_pending_mu_);
                gw_pending_.push_back({s->agent_id, cmd});
                ++count;
            }
        }
        return count;
    }

    struct GatewayPendingCmd {
        std::string agent_id;
        pb::CommandRequest cmd;
    };

    std::vector<GatewayPendingCmd> drain_gateway_pending() {
        std::lock_guard lock(gw_pending_mu_);
        auto result = std::move(gw_pending_);
        gw_pending_.clear();
        return result;
    }

    bool has_any() const {
        std::lock_guard lock(mu_);
        return !agents_.empty();
    }

    std::string display_name(const std::string& agent_id) const {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it != agents_.end() && !it->second->hostname.empty())
            return it->second->hostname;
        if (agent_id.size() > 12) return agent_id.substr(0, 12);
        return agent_id;
    }

    // Build JSON array of all agents for the web UI (structured).
    nlohmann::json to_json_obj() const {
        std::lock_guard lock(mu_);

        nlohmann::json arr = nlohmann::json::array();
        for (const auto& s : agents_ | std::views::values) {
            arr.push_back({{"agent_id", s->agent_id},
                           {"hostname", s->hostname},
                           {"os", s->os},
                           {"arch", s->arch},
                           {"agent_version", s->agent_version}});
        }
        return arr;
    }

    // Build JSON array as a serialized string.
    std::string to_json() const { return to_json_obj().dump(); }

    // Per-action description map: "plugin.action" → human-readable description.
    // Kept server-side so agents don't need proto changes to report action help.
    static const std::unordered_map<std::string, std::string>& action_descriptions() {
        static const std::unordered_map<std::string, std::string> m = {
            // example
            {"example.ping",            "Returns a 'pong' response"},
            {"example.echo",            "Echoes back the supplied message parameter"},
            // status
            {"status.version",          "Agent version, build number, and git commit hash"},
            {"status.info",             "Platform OS, architecture, and hostname"},
            {"status.health",           "Uptime, current timestamp, and memory RSS"},
            {"status.plugins",          "Installed plugins with version and description"},
            {"status.modules",          "Loaded modules with version and status"},
            {"status.connection",       "Server address, TLS status, debug and verbose settings"},
            {"status.switch",           "Switch address, session ID, connected since, reconnect count"},
            {"status.config",           "Full agent configuration dump"},
            // processes
            {"processes.list",          "Enumerate all running processes (PID and name)"},
            {"processes.query",         "Filter processes by case-insensitive name match"},
            // hardware
            {"hardware.manufacturer",   "System manufacturer string"},
            {"hardware.model",          "System model / product name"},
            {"hardware.bios",           "BIOS/UEFI vendor, version, and release date"},
            {"hardware.processors",     "Installed CPUs with model, cores, threads, clock speed"},
            {"hardware.memory",         "Installed memory modules (DIMMs) with size and type"},
            {"hardware.disks",          "Physical disk drives with size and media type"},
            // os_info
            {"os_info.os_name",         "Full OS product name"},
            {"os_info.os_version",      "OS version string"},
            {"os_info.os_build",        "OS build identifier"},
            {"os_info.os_arch",         "CPU architecture"},
            {"os_info.uptime",          "System uptime in seconds and human-readable form"},
            // services
            {"services.list",           "Installed services with name, status, and startup type"},
            {"services.running",        "Only currently running services"},
            {"services.set_start_mode", "Change a service's startup type (automatic/manual/disabled)"},
            // users
            {"users.logged_on",         "Currently logged-on users"},
            {"users.sessions",          "Active interactive sessions"},
            {"users.local_users",       "Enumerate local user accounts"},
            {"users.local_admins",      "Members of the local Administrators group"},
            {"users.group_members",     "Members of a specified local group"},
            {"users.primary_user",      "Primary user (most frequent login)"},
            {"users.session_history",   "Historical login/logout session records"},
            // tags
            {"tags.set",                "Set a tag key-value pair"},
            {"tags.get",                "Get a tag value by key"},
            {"tags.get_all",            "Get all tags"},
            {"tags.delete",             "Delete a tag by key"},
            {"tags.check",              "Check if a tag key exists"},
            {"tags.clear",              "Clear all tags"},
            {"tags.count",              "Count total tags"},
            // registry
            {"registry.get_value",      "Read a Windows registry value"},
            {"registry.set_value",      "Write a Windows registry value"},
            {"registry.delete_value",   "Delete a Windows registry value"},
            {"registry.delete_key",     "Delete a Windows registry key"},
            {"registry.key_exists",     "Check if a registry key exists"},
            {"registry.enumerate_keys", "List subkeys under a registry key"},
            {"registry.enumerate_values","List values in a registry key"},
            {"registry.get_user_value", "Get a registry value for a specific user SID"},
            // filesystem
            {"filesystem.exists",       "Check if a path exists, report type and size"},
            {"filesystem.list_dir",     "List directory contents (max 1000 entries)"},
            {"filesystem.file_hash",    "Compute SHA-256 (or SHA-1) hash of a file"},
            {"filesystem.create_temp",  "Create a secure temporary file (owner-only permissions)"},
            {"filesystem.create_temp_dir","Create a secure temporary directory (owner-only permissions)"},
            // content_dist
            {"content_dist.stage",      "Download a file to staging directory with hash verification"},
            {"content_dist.execute_staged","Execute a previously staged file"},
            {"content_dist.list_staged", "List files in the staging directory"},
            {"content_dist.cleanup",    "Remove staged files older than N hours"},
            // script_exec
            {"script_exec.exec",        "Execute a command with arguments (no shell interpretation)"},
            {"script_exec.powershell",  "Run a PowerShell script (Windows only)"},
            {"script_exec.bash",        "Run a bash script (Linux/macOS only)"},
            // windows_updates
            {"windows_updates.installed","List recently installed updates or packages"},
            {"windows_updates.missing", "List available updates or packages not yet installed"},
            // agent_logging
            {"agent_logging.get_log",   "Return the last N lines of the agent log file"},
            {"agent_logging.get_key_files","List important agent files with sizes and modification times"},
            // installed_apps
            {"installed_apps.list",     "List all installed applications"},
            {"installed_apps.query",    "Search for an application by name (partial match)"},
            // network_config
            {"network_config.adapters", "Network adapters with MAC, speed, and status"},
            {"network_config.ip_addresses","Assigned IP addresses with subnet and gateway"},
            {"network_config.dns_servers","Configured DNS servers per adapter"},
            {"network_config.proxy",    "System proxy configuration"},
            // network_actions
            {"network_actions.flush_dns","Flush the DNS resolver cache"},
            {"network_actions.ping",    "Ping a host (params: host, count)"},
            // netstat
            {"netstat.netstat_list",    "Active TCP/UDP connections and listening sockets with owning PID"},
            // device_identity
            {"device_identity.device_name","Machine hostname"},
            {"device_identity.domain",  "DNS/AD domain and join status"},
            {"device_identity.ou",      "Active Directory organizational unit path"},
            // discovery
            {"discovery.scan_subnet",   "ARP scan + ping sweep of a subnet to find live hosts"},
            // firewall
            {"firewall.state",          "Firewall state per profile/backend"},
            {"firewall.rules",          "List firewall rules (summary)"},
            // certificates
            {"certificates.list",       "List certificates in system stores"},
            {"certificates.details",    "Get details for a certificate by thumbprint"},
            {"certificates.delete",     "Delete a certificate by thumbprint from a given store"},
            // event_logs
            {"event_logs.errors",       "Recent error events from a specified log"},
            {"event_logs.query",        "Search events by keyword"},
            // wmi
            {"wmi.query",              "Run a WQL SELECT query"},
            {"wmi.get_instance",       "Get all properties of a WMI class instance"},
            // bitlocker
            {"bitlocker.state",        "BitLocker / LUKS / FileVault status per volume"},
            // antivirus
            {"antivirus.products",     "List installed antivirus products"},
            {"antivirus.status",       "Windows Defender detailed status"},
            // http_client
            {"http_client.download",   "Download a file from URL with optional hash verification"},
            {"http_client.get",        "HTTP GET a URL, return status and body"},
            {"http_client.head",       "HTTP HEAD a URL, return status and headers"},
            // chargen
            {"chargen.chargen_start",  "Begin generating rotating ASCII character lines (RFC 864)"},
            {"chargen.chargen_stop",   "Stop all running chargen sessions"},
            // ioc
            {"ioc.check",             "Check indicators of compromise against local endpoint state"},
            // quarantine
            {"quarantine.quarantine",  "Isolate device from network, whitelisting management server"},
            {"quarantine.unquarantine","Remove quarantine firewall rules and restore network access"},
            {"quarantine.status",      "Check whether quarantine rules are currently active"},
            {"quarantine.whitelist",   "Add or remove IPs from an active quarantine whitelist"},
            // agent_actions
            {"agent_actions.set_log_level","Change the spdlog log level at runtime"},
            {"agent_actions.info",     "Return agent runtime info from config context"},
            // software_actions
            {"software_actions.list_upgradable","List packages/apps that can be upgraded (read-only)"},
            {"software_actions.installed_count","Quick count of installed packages or apps"},
            // network_diag
            {"network_diag.listening",  "List listening TCP ports"},
            {"network_diag.connections","List established TCP connections"},
            // msi_packages
            {"msi_packages.list",       "List all installed MSI packages"},
            {"msi_packages.product_codes","Compact list of installed MSI product code GUIDs"},
            // sccm
            {"sccm.client_version",     "Check if SCCM client is installed and report version"},
            {"sccm.site",              "Get SCCM site assignment info"},
            // storage
            {"storage.set",            "Store a key-value pair in persistent storage"},
            {"storage.get",            "Retrieve a value by key from persistent storage"},
            {"storage.delete",         "Delete a key from persistent storage"},
            {"storage.list",           "List keys matching a prefix"},
            {"storage.clear",          "Delete all keys for this plugin"},
            // interaction
            {"interaction.notify",     "Show a desktop notification/toast message"},
            {"interaction.message_box","Show a modal message dialog, return button clicked"},
            {"interaction.input",      "Show a text input dialog, return entered text"},
            {"interaction.survey",     "Show a multi-question survey form, collect responses"},
            {"interaction.set_dnd",    "Enable or disable Do Not Disturb mode"},
            // asset_tags
            {"asset_tags.sync",        "Push current structured tags from server; detect changes"},
            {"asset_tags.status",      "Report locally cached tags and sync metadata"},
            {"asset_tags.get",         "Get a specific structured tag value by category key"},
            {"asset_tags.changes",     "Report the change log (what changed and when)"},
            // procfetch
            {"procfetch.procfetch_fetch","Enumerate processes with PID, name, path, and SHA-1 hash"},
            // sockwho
            {"sockwho.sockwho_list",   "Map open sockets to owning processes (PID, name, path)"},
            // wol
            {"wol.wake",              "Send a Wake-on-LAN magic packet to a MAC address"},
            {"wol.check",             "Ping a host to verify it responded to WoL wake"},
            // vuln_scan
            {"vuln_scan.scan",        "Full vulnerability scan (CVE + configuration checks)"},
            {"vuln_scan.cve_scan",    "CVE-only: match installed software against known CVEs"},
            {"vuln_scan.config_scan", "Configuration and compliance checks only"},
            {"vuln_scan.summary",     "Quick severity counts from a full vulnerability scan"},
            // wifi
            {"wifi.list_networks",    "Scan for visible WiFi networks (SSID, signal, security)"},
            {"wifi.connected",        "Currently connected WiFi network info"},
            // diagnostics
            {"diagnostics.log_level", "Read current agent log level from config"},
            {"diagnostics.certificates","List TLS certificate paths and whether they exist"},
            {"diagnostics.connection_info","Server address, TLS, session, channel state, latency, uptime"},
            // tar (Timeline Activity Record)
            {"tar.status",            "Current TAR collection status, event counts, and DB size"},
            {"tar.query",             "Query recorded timeline events by type and time range"},
            {"tar.snapshot",          "Trigger an immediate full-state snapshot"},
            {"tar.export",            "Export timeline events as structured data"},
            {"tar.configure",         "Update TAR collection intervals and retention settings"},
            {"tar.collect_fast",      "Run fast collectors (processes + network connections)"},
            {"tar.collect_slow",      "Run slow collectors (services + users + installed apps)"},
        };
        return m;
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

        const auto& descs = action_descriptions();
        nlohmann::json plugins_arr = nlohmann::json::array();
        nlohmann::json commands_arr = nlohmann::json::array();

        for (const auto* pm : sorted) {
            nlohmann::json pj;
            pj["name"] = pm->name;
            pj["version"] = pm->version;
            pj["description"] = pm->description;

            // Build actions as objects with name + description
            nlohmann::json actions_arr = nlohmann::json::array();
            for (const auto& act : pm->actions) {
                nlohmann::json aj;
                aj["name"] = act;
                auto it = descs.find(pm->name + "." + act);
                aj["description"] = it != descs.end() ? it->second : "";
                actions_arr.push_back(std::move(aj));
            }
            pj["actions"] = std::move(actions_arr);

            plugins_arr.push_back(std::move(pj));

            // Build command strings: bare plugin name + plugin action
            commands_arr.push_back(pm->name);
            for (const auto& act : pm->actions) {
                commands_arr.push_back(pm->name + " " + act);
            }
        }

        return nlohmann::json({{"plugins", plugins_arr}, {"commands", commands_arr}}).dump();
    }

    // Render help table as HTML fragment (thead + tbody rows).
    // Optional filter narrows to a single plugin.
    std::string help_html(std::string_view filter = "") const {
        std::lock_guard lock(mu_);

        std::unordered_map<std::string, const PluginMeta*> best;
        for (const auto& s : agents_ | std::views::values)
            for (const auto& pm : s->plugin_meta) {
                auto it = best.find(pm.name);
                if (it == best.end() || pm.actions.size() > it->second->actions.size())
                    best[pm.name] = &pm;
            }

        std::vector<const PluginMeta*> sorted;
        sorted.reserve(best.size());
        for (const auto* pm : best | std::views::values)
            sorted.push_back(pm);
        std::ranges::sort(sorted, [](const PluginMeta* a, const PluginMeta* b) {
            return a->name < b->name;
        });

        if (!filter.empty()) {
            std::erase_if(sorted, [&](const PluginMeta* pm) { return pm->name != filter; });
        }

        const auto& descs = action_descriptions();
        auto esc = [](std::string_view s) {
            std::string out;
            out.reserve(s.size());
            for (char c : s) {
                switch (c) {
                    case '&':  out += "&amp;";  break;
                    case '<':  out += "&lt;";   break;
                    case '>':  out += "&gt;";   break;
                    case '"':  out += "&quot;";  break;
                    default:   out += c;
                }
            }
            return out;
        };

        std::string html;
        int row_count = 0;

        for (const auto* pm : sorted) {
            if (pm->actions.empty()) {
                html += "<tr class=\"result-row\" onclick=\"toggleDetail(this)\">"
                        "<td class=\"col-agent\" title=\"" + esc(pm->name) + "\">" + esc(pm->name) + "</td>"
                        "<td title=\"\u2014\">\u2014</td>"
                        "<td title=\"" + esc(pm->description) + "\">" + esc(pm->description) + "</td></tr>"
                        "<tr class=\"result-detail\"><td colspan=\"3\"><div class=\"detail-content\">"
                        "<div class=\"detail-label\">Plugin</div><div class=\"detail-value\">" + esc(pm->name) + "</div>"
                        "<div class=\"detail-label\">Action</div><div class=\"detail-value\">\u2014</div>"
                        "<div class=\"detail-label\">Description</div><div class=\"detail-value\">" + esc(pm->description) + "</div>"
                        "</div></td></tr>";
                ++row_count;
            } else {
                for (const auto& act : pm->actions) {
                    auto key = pm->name + "." + act;
                    auto it = descs.find(key);
                    std::string desc = it != descs.end() ? it->second : "";
                    html += "<tr class=\"result-row\" onclick=\"toggleDetail(this)\">"
                            "<td class=\"col-agent\" title=\"" + esc(pm->name) + "\">" + esc(pm->name) + "</td>"
                            "<td title=\"" + esc(act) + "\">" + esc(act) + "</td>"
                            "<td title=\"" + esc(desc) + "\">" + esc(desc) + "</td></tr>"
                            "<tr class=\"result-detail\"><td colspan=\"3\"><div class=\"detail-content\">"
                            "<div class=\"detail-label\">Plugin</div><div class=\"detail-value\">" + esc(pm->name) + "</div>"
                            "<div class=\"detail-label\">Action</div><div class=\"detail-value\">" + esc(act) + "</div>"
                            "<div class=\"detail-label\">Description</div><div class=\"detail-value\">" + esc(desc) + "</div>"
                            "</div></td></tr>";
                    ++row_count;
                }
            }
        }

        // Wrap: context span + thead + tbody in a single OOB-capable response
        std::string context = filter.empty() ? "help \u2014 all plugins"
                                             : "help " + std::string(filter);
        std::string result;
        result += "<span id=\"result-context\" hx-swap-oob=\"innerHTML\" style=\"font-size:0.75rem;color:#8b949e\">"
                  + esc(context) + "</span>";
        result += "<tr id=\"help-thead-row\" hx-swap-oob=\"innerHTML:#results-thead\">"
                  "<th class=\"col-agent\">Plugin</th><th>Action</th><th>Description</th></tr>";
        result += "<span id=\"help-row-count\" hx-swap-oob=\"innerHTML:#row-count\">"
                  + std::to_string(row_count) + "</span>";
        result += html;
        return result;
    }

    // Render autocomplete dropdown items as HTML.
    std::string autocomplete_html(std::string_view query) const {
        std::lock_guard lock(mu_);

        std::string q{query};
        std::ranges::transform(q, q.begin(), ::tolower);

        std::unordered_map<std::string, const PluginMeta*> best;
        for (const auto& s : agents_ | std::views::values)
            for (const auto& pm : s->plugin_meta) {
                auto it = best.find(pm.name);
                if (it == best.end() || pm.actions.size() > it->second->actions.size())
                    best[pm.name] = &pm;
            }

        const auto& descs = action_descriptions();
        auto esc = [](std::string_view s) {
            std::string out;
            out.reserve(s.size());
            for (char c : s) {
                switch (c) {
                    case '&':  out += "&amp;";  break;
                    case '<':  out += "&lt;";   break;
                    case '>':  out += "&gt;";   break;
                    case '"':  out += "&quot;";  break;
                    default:   out += c;
                }
            }
            return out;
        };

        // Build sorted command list with descriptions
        struct CmdEntry { std::string cmd; std::string desc; };
        std::vector<CmdEntry> all_cmds;

        // "help" pseudo-command
        all_cmds.push_back({"help", "List all plugins and actions"});

        for (const auto& [name, pm] : best) {
            all_cmds.push_back({pm->name, pm->description});
            for (const auto& act : pm->actions) {
                auto key = pm->name + "." + act;
                auto it = descs.find(key);
                all_cmds.push_back({pm->name + " " + act,
                                    it != descs.end() ? it->second : pm->description});
            }
        }

        // Filter by prefix
        std::vector<const CmdEntry*> matches;
        for (const auto& e : all_cmds) {
            if (e.cmd.starts_with(q) && e.cmd != q)
                matches.push_back(&e);
        }
        std::ranges::sort(matches, [](const CmdEntry* a, const CmdEntry* b) {
            return a->cmd < b->cmd;
        });
        if (matches.size() > 15) matches.resize(15);

        std::string html;
        for (const auto* m : matches) {
            html += "<div class=\"ac-item\" data-cmd=\"" + esc(m->cmd) + "\">"
                    "<span>" + esc(m->cmd) + "</span>";
            if (!m->desc.empty())
                html += "<span class=\"ac-desc\">" + esc(m->desc) + "</span>";
            html += "</div>";
        }
        return html;
    }

    // Render command palette instruction results as HTML.
    std::string palette_html(std::string_view query) const {
        std::lock_guard lock(mu_);

        std::string q{query};
        std::ranges::transform(q, q.begin(), ::tolower);

        std::unordered_map<std::string, const PluginMeta*> best;
        for (const auto& s : agents_ | std::views::values)
            for (const auto& pm : s->plugin_meta) {
                auto it = best.find(pm.name);
                if (it == best.end() || pm.actions.size() > it->second->actions.size())
                    best[pm.name] = &pm;
            }

        const auto& descs = action_descriptions();
        auto esc = [](std::string_view s) {
            std::string out;
            out.reserve(s.size());
            for (char c : s) {
                switch (c) {
                    case '&':  out += "&amp;";  break;
                    case '<':  out += "&lt;";   break;
                    case '>':  out += "&gt;";   break;
                    case '"':  out += "&quot;";  break;
                    default:   out += c;
                }
            }
            return out;
        };

        struct Entry { std::string name; std::string desc; std::string plugin; std::string action; };
        std::vector<Entry> results;
        std::unordered_set<std::string> seen_plugins;

        for (const auto& [pname, pm] : best) {
            for (const auto& act : pm->actions) {
                auto key = pm->name + "." + act;
                auto it = descs.find(key);
                std::string desc = it != descs.end() ? it->second : pm->description;
                std::string full = pm->name + " " + act;
                std::string full_lower = full;
                std::ranges::transform(full_lower, full_lower.begin(), ::tolower);
                std::string desc_lower = desc;
                std::ranges::transform(desc_lower, desc_lower.begin(), ::tolower);
                if (full_lower.find(q) != std::string::npos || desc_lower.find(q) != std::string::npos) {
                    results.push_back({full, desc, pm->name, act});
                    seen_plugins.insert(pm->name);
                }
            }
            // Also match just plugin name
            std::string pname_lower = pm->name;
            std::ranges::transform(pname_lower, pname_lower.begin(), ::tolower);
            if (pname_lower.find(q) != std::string::npos && !pm->actions.empty()
                && !seen_plugins.contains(pm->name)) {
                auto& first_act = pm->actions.front();
                auto key = pm->name + "." + first_act;
                auto it = descs.find(key);
                std::string desc = it != descs.end() ? it->second : pm->description;
                results.push_back({pm->name + " " + first_act, desc, pm->name, first_act});
            }
        }

        std::ranges::sort(results, [](const Entry& a, const Entry& b) { return a.name < b.name; });
        if (results.size() > 8) results.resize(8);

        std::string html;
        if (!results.empty()) {
            html += "<div class=\"cmd-section-header\">Instructions</div>";
        }
        for (size_t i = 0; i < results.size(); ++i) {
            const auto& r = results[i];
            html += "<div class=\"cmd-result\" data-index=\"" + std::to_string(i) + "\""
                    " data-type=\"instruction\" data-plugin=\"" + esc(r.plugin) + "\""
                    " data-action=\"" + esc(r.action) + "\">"
                    "<span class=\"cmd-result-name\">" + esc(r.name) + "</span>"
                    "<span class=\"cmd-result-desc\">" + esc(r.desc) + "</span>"
                    "<span class=\"cmd-result-type badge badge-info\">Instruction</span>"
                    "</div>";
        }
        return html;
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
                                            const TagStore* tag_store,
                                            const CustomPropertiesStore* props_store = nullptr) const {
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
                // props:X lookups (custom properties, Phase 7.6)
                if (key.starts_with("props.")) {
                    auto prop_key = key.substr(6);
                    if (props_store)
                        return props_store->get_value(id, prop_key);
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
    std::mutex gw_pending_mu_;
    std::vector<GatewayPendingCmd> gw_pending_;
};

// -- SSE sink state (per-connection, shared with content provider) -------------

// html_escape is provided by web_utils.hpp in namespace yuzu::server.
// Bring it into the detail namespace so AgentServiceImpl can use it unqualified.
using yuzu::server::html_escape;

struct SseSinkState {
    std::mutex mu;
    std::condition_variable cv;
    std::deque<SseEvent> queue;
    std::atomic<bool> closed = false;
    std::size_t sub_id = 0;
};

// -- SSE helpers --------------------------------------------------------------

// Format an SSE message.  The SSE spec requires every line of a multi-line
// data field to carry its own "data: " prefix; the browser's EventSource
// parser re-joins them with '\n'.  Without this, embedded newlines in agent
// output cause silent truncation — only the first line reaches the browser.
std::string format_sse(const SseEvent& ev) {
    std::string out;
    out += "event: ";
    out += ev.event_type;
    out += '\n';
    std::string_view d{ev.data};
    if (d.empty()) {
        out += "data: \n";
    } else {
        std::size_t pos = 0;
        while (pos < d.size()) {
            auto nl = d.find('\n', pos);
            out += "data: ";
            out.append(d.substr(pos, (nl == std::string_view::npos ? d.size() : nl) - pos));
            out += '\n';
            if (nl == std::string_view::npos) break;
            pos = nl + 1;
        }
    }
    out += '\n'; // blank line terminates the event
    return out;
}

// -- SSE content provider callback --------------------------------------------

bool sse_content_provider(const std::shared_ptr<SseSinkState>& state, size_t /*offset*/,
                          httplib::DataSink& sink) {
    std::unique_lock<std::mutex> lk(state->mu);
    // Keep the interval well under httplib's Keep-Alive timeout (5s)
    // to prevent the browser from closing the SSE connection due to
    // inactivity.
    state->cv.wait_for(lk, std::chrono::seconds(3),
                       [&state] { return !state->queue.empty() || state->closed.load(); });

    if (state->closed.load()) {
        return false;
    }

    while (!state->queue.empty()) {
        auto& ev = state->queue.front();
        std::string sse = format_sse(ev);
        // httplib's chunked provider assembles each sink.write() into a
        // single HTTP chunk frame (hex-size + CRLF + data + CRLF) and
        // flushes it in one send() call — the browser processes each chunk
        // eagerly.  Write in <=8 KB slices to stay within typical TCP send
        // buffer limits and avoid partial-write failures.
        const char* p = sse.data();
        size_t rem = sse.size();
        constexpr size_t kMaxSlice = 8192;
        while (rem > 0) {
            auto n = std::min(rem, kMaxSlice);
            if (!sink.write(p, n)) return false;
            p += n;
            rem -= n;
        }
        state->queue.pop_front();
    }

    const char* keepalive = "event: heartbeat\ndata: \n\n";
    if (!sink.write(keepalive, std::strlen(keepalive))) {
        spdlog::debug("SSE heartbeat write failed (client disconnected)");
        return false;
    }
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
    void set_notification_store(NotificationStore* store) { notification_store_ = store; }
    void set_webhook_store(WebhookStore* store) { webhook_store_ = store; }
    void set_inventory_store(InventoryStore* store) { inventory_store_ = store; }

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

        // Create notification for agent enrollment
        if (notification_store_ && notification_store_->is_open()) {
            notification_store_->create(
                "success", "Agent Enrolled",
                "Agent " + info.agent_id() + " (" + info.hostname() + ") enrolled successfully");
        }

        // Fire webhook for agent enrollment
        if (webhook_store_ && webhook_store_->is_open()) {
            nlohmann::json payload = {{"event", "agent.registered"},
                                      {"agent_id", info.agent_id()},
                                      {"hostname", info.hostname()},
                                      {"os", info.platform().os()},
                                      {"arch", info.platform().arch()},
                                      {"agent_version", info.agent_version()}};
            webhook_store_->fire_event("agent.registered", payload.dump());
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

        // Read loop — process responses from the agent
        pb::CommandResponse resp;
        while (stream->Read(&resp)) {
            registry_.touch_activity(agent_id);
            if (resp.status() == pb::CommandResponse::RUNNING) {
                // Intercept __timing__ metadata
                if (resp.output().starts_with("__timing__|")) {
                    // Extract exec_ms=N from "__timing__|exec_ms=123"
                    auto payload = resp.output().substr(11);
                    auto eq = payload.find('=');
                    auto ms = (eq != std::string::npos) ? payload.substr(eq + 1) : payload;
                    bus_.publish("timing",
                        "<strong id=\"stat-agent\" hx-swap-oob=\"true\">" +
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
                            bus_.publish("timing",
                                "<strong id=\"stat-network\" hx-swap-oob=\"true\">" +
                                std::to_string(elapsed) + " ms</strong>");
                        }
                    }
                }

                // Determine the plugin from command_id prefix (format: plugin-timestamp)
                std::string plugin = extract_plugin(resp.command_id());

                // Publish each row as its own SSE event — small events
                // stream reliably; giant events (500KB+) stall browsers.
                publish_output_rows(agent_id, plugin, resp.output());

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
                {
                    std::string badge_cls = (status_str == "done") ? "badge-done" : "badge-error";
                    std::string badge_text = (status_str == "done") ? "DONE" : "ERROR";
                    bus_.publish("command-status",
                        "<span id=\"status-badge\" class=\"" + badge_cls +
                        "\" hx-swap-oob=\"outerHTML\">" + badge_text + "</span>");
                }

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

                // Create notification on execution failure
                if (resp.status() != pb::CommandResponse::SUCCESS && notification_store_ &&
                    notification_store_->is_open()) {
                    std::string err_msg = resp.has_error() ? resp.error().message() : "unknown";
                    notification_store_->create(
                        "error", "Execution Failed",
                        "Command " + resp.command_id() + " on agent " + agent_id +
                            " failed: " + err_msg);
                }

                // Fire webhook on execution completion
                if (webhook_store_ && webhook_store_->is_open()) {
                    nlohmann::json wh_payload = {
                        {"event", "execution.completed"},
                        {"command_id", resp.command_id()},
                        {"agent_id", agent_id},
                        {"status", status_str},
                        {"exit_code", resp.exit_code()}};
                    if (resp.has_error()) {
                        wh_payload["error"] = resp.error().message();
                    }
                    webhook_store_->fire_event("execution.completed", wh_payload.dump());
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
                        bus_.publish("timing",
                            "<strong id=\"stat-total\" hx-swap-oob=\"true\">" +
                            std::to_string(total_ms) + " ms</strong>");
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
        output_row_count_.store(0, std::memory_order_relaxed);
    }

    // Process a CommandResponse forwarded from the gateway.
    // Mirrors the Subscribe read loop logic for SSE, storage, analytics.
    void process_gateway_response(const std::string& agent_id,
                                   const pb::CommandResponse& resp) {
        if (resp.status() == pb::CommandResponse::RUNNING) {
            // Intercept __timing__ metadata
            if (resp.output().starts_with("__timing__|")) {
                auto payload = resp.output().substr(11);
                auto eq = payload.find('=');
                auto ms = (eq != std::string::npos) ? payload.substr(eq + 1) : payload;
                bus_.publish("timing",
                    "<strong id=\"stat-agent\" hx-swap-oob=\"true\">" +
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
                        bus_.publish("timing",
                            "<strong id=\"stat-network\" hx-swap-oob=\"true\">" +
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
            spdlog::info("[gateway] Command {} completed: status={}, exit_code={}",
                         resp.command_id(), static_cast<int>(resp.status()), resp.exit_code());

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
            {
                std::string badge_cls = (status_str == "done") ? "badge-done" : "badge-error";
                std::string badge_text = (status_str == "done") ? "DONE" : "ERROR";
                bus_.publish("command-status",
                    "<span id=\"status-badge\" class=\"" + badge_cls +
                    "\" hx-swap-oob=\"outerHTML\">" + badge_text + "</span>");
            }

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

            if (resp.status() != pb::CommandResponse::SUCCESS && notification_store_ &&
                notification_store_->is_open()) {
                std::string err_msg = resp.has_error() ? resp.error().message() : "unknown";
                notification_store_->create(
                    "error", "Execution Failed",
                    "Command " + resp.command_id() + " on agent " + agent_id +
                        " failed: " + err_msg);
            }

            if (webhook_store_ && webhook_store_->is_open()) {
                nlohmann::json wh_payload = {
                    {"event", "execution.completed"},
                    {"command_id", resp.command_id()},
                    {"agent_id", agent_id},
                    {"status", status_str},
                    {"exit_code", resp.exit_code()}};
                if (resp.has_error()) {
                    wh_payload["error"] = resp.error().message();
                }
                webhook_store_->fire_event("execution.completed", wh_payload.dump());
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
                    bus_.publish("timing",
                        "<strong id=\"stat-total\" hx-swap-oob=\"true\">" +
                        std::to_string(total_ms) + " ms</strong>");
                    cmd_send_times_.erase(it);
                }
                cmd_first_seen_.erase(resp.command_id());
            }
        }
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

public:
    // ── Server-rendered SSE row helpers ──────────────────────────────────────

    static inline const std::vector<std::string> kDefaultColumns{"Agent", "Output"};

    static const std::vector<std::string>& columns_for_plugin(const std::string& plugin) {
        static const std::unordered_map<std::string, std::vector<std::string>> kSchemas{
            {"chargen",          {"Agent", "Output"}},
            {"procfetch",        {"Agent", "PID", "Name", "Path", "SHA-1"}},
            {"netstat",          {"Agent", "Proto", "Local Addr", "Local Port",
                                  "Remote Addr", "Remote Port", "State", "PID"}},
            {"sockwho",          {"Agent", "PID", "Name", "Path", "Proto",
                                  "Local Addr", "Local Port", "Remote Addr", "Remote Port", "State"}},
            {"vuln_scan",        {"Agent", "Severity", "Category", "Title", "Detail"}},
        };
        // key|value schema plugins
        static const std::vector<std::string> kKeyValue{"Agent", "Key", "Value"};
        static const std::unordered_set<std::string> kKeyValuePlugins{
            "status", "device_identity", "os_info", "hardware", "users",
            "installed_apps", "msi_packages", "network_config", "diagnostics",
            "agent_actions", "processes", "services", "filesystem",
            "network_diag", "network_actions", "firewall", "antivirus",
            "bitlocker", "windows_updates", "event_logs", "sccm",
            "script_exec", "software_actions"};

        auto it = kSchemas.find(plugin);
        if (it != kSchemas.end()) return it->second;
        if (kKeyValuePlugins.contains(plugin)) return kKeyValue;
        return kDefaultColumns;
    }

    static std::string thead_for_plugin(const std::string& plugin) {
        auto& cols = columns_for_plugin(plugin);
        std::string html = "<tr>";
        for (size_t i = 0; i < cols.size(); ++i) {
            html += (i == 0) ? "<th class=\"col-agent\">" : "<th>";
            html += html_escape(cols[i]);
            html += "</th>";
        }
        html += "</tr>";
        return html;
    }

    // Find the next unescaped pipe ('|' not preceded by '\\').
    static size_t find_unescaped_pipe(const std::string& s, size_t pos) {
        while (pos < s.size()) {
            auto p = s.find('|', pos);
            if (p == std::string::npos) return std::string::npos;
            if (p > 0 && s[p - 1] == '\\') { pos = p + 1; continue; }
            return p;
        }
        return std::string::npos;
    }

    // Unescape \\| → | in a field value.
    static std::string unescape_pipes(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '\\' && i + 1 < s.size() && s[i + 1] == '|') continue;
            out += s[i];
        }
        return out;
    }

    // Split one pipe-delimited line into table cells using the plugin schema.
    // Respects \| escape sequences emitted by plugins (procfetch, sockwho, vuln_scan, ioc).
    static std::vector<std::string> split_fields(const std::string& plugin,
                                                  const std::string& line) {
        // vuln_scan: severity|category|title|detail (4+ fields, last is remainder)
        if (plugin == "vuln_scan") {
            std::vector<std::string> parts;
            size_t pos = 0;
            for (int i = 0; i < 3; ++i) {
                auto p = find_unescaped_pipe(line, pos);
                if (p == std::string::npos) { parts.push_back(unescape_pipes(line.substr(pos))); return parts; }
                parts.push_back(unescape_pipes(line.substr(pos, p - pos)));
                pos = p + 1;
            }
            parts.push_back(unescape_pipes(line.substr(pos))); // remainder = detail
            return parts;
        }
        // key|value plugins: split into exactly 2 (key, rest)
        auto& cols = columns_for_plugin(plugin);
        if (cols.size() == 3) { // Agent + Key + Value
            auto sep = find_unescaped_pipe(line, 0);
            if (sep != std::string::npos)
                return {unescape_pipes(line.substr(0, sep)), unescape_pipes(line.substr(sep + 1))};
            return {unescape_pipes(line), ""};
        }
        // Default: split on all pipes
        std::vector<std::string> parts;
        size_t pos = 0;
        while (pos <= line.size()) {
            auto p = find_unescaped_pipe(line, pos);
            if (p == std::string::npos) { parts.push_back(unescape_pipes(line.substr(pos))); break; }
            parts.push_back(unescape_pipes(line.substr(pos, p - pos)));
            pos = p + 1;
        }
        return parts;
    }

    // Render <tr> pair (data row + detail drawer) for one output line.
    static std::string render_row(const std::string& agent_name,
                                   const std::string& plugin,
                                   const std::string& line,
                                   const std::vector<std::string>& col_names) {
        auto fields = split_fields(plugin, line);

        // Build cells: agent_name + fields
        std::vector<std::string> cells;
        cells.reserve(fields.size() + 1);
        cells.push_back(agent_name);
        for (auto& f : fields) cells.push_back(f);

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
            auto label = (i < col_names.size()) ? col_names[i]
                                                 : ("Column " + std::to_string(i + 1));
            html += "<div class=\"detail-label\">" + html_escape(label) + "</div>";
            html += "<div class=\"detail-value\">" + html_escape(cells[i]) + "</div>";
        }
        html += "</div></td></tr>";
        return html;
    }

    // render_output_rows removed — publish_output_rows emits one SSE
    // event per row for reliable browser streaming.

    // Publish each output line as its own SSE event for reliable streaming.
    // Each event includes OOB swaps for the row counter and empty-state removal
    // so the browser needs zero JS to keep the UI in sync.
    void publish_output_rows(const std::string& agent_id,
                              const std::string& plugin,
                              const std::string& raw_output) {
        if (raw_output.empty()) return;
        auto agent_name = registry_.display_name(agent_id);
        auto& col_names = columns_for_plugin(plugin);
        size_t pos = 0;
        while (pos < raw_output.size()) {
            auto nl = raw_output.find('\n', pos);
            std::string line = (nl == std::string::npos)
                                   ? raw_output.substr(pos)
                                   : raw_output.substr(pos, nl - pos);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) {
                // fetch_add returns pre-increment value; +1 gives 1-based row number
                auto count = output_row_count_.fetch_add(1, std::memory_order_relaxed) + 1;
                auto html = render_row(agent_name, plugin, line, col_names);
                // OOB: live row count
                html += "<span id=\"row-count\" hx-swap-oob=\"true\">";
                html += std::to_string(count);
                html += "</span>";
                // OOB: remove empty-state placeholder on first row only
                if (count == 1)
                    html += "<tr id=\"empty-row\" hx-swap-oob=\"delete\"></tr>";
                bus_.publish("output", html);
            }
            pos = (nl == std::string::npos) ? raw_output.size() : nl + 1;
        }
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
    // Best-effort row counter for the dashboard UI.  Reset on new command
    // dispatch.  Under concurrent commands the count may briefly glitch
    // (acceptable for a single-user dashboard; per-command counters would
    // add unnecessary complexity).
    std::atomic<size_t> output_row_count_{0};
    bool require_client_identity_{false};
    bool gateway_mode_{false};
    UpdateRegistry* update_registry_{nullptr};
    ResponseStore* response_store_{nullptr};
    TagStore* tag_store_{nullptr};
    AnalyticsEventStore* analytics_store_{nullptr};
    AgentHealthStore* health_store_{nullptr};
    ManagementGroupStore* mgmt_group_store_{nullptr};
    NotificationStore* notification_store_{nullptr};
    WebhookStore* webhook_store_{nullptr};
    InventoryStore* inventory_store_{nullptr};
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
    void set_inventory_store(InventoryStore* store) { inventory_store_ = store; }

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

        // Persist inventory data via InventoryStore (Issue 7.17)
        if (inventory_store_ && inventory_store_->is_open()) {
            int64_t collected_epoch = 0;
            if (request->has_collected_at()) {
                collected_epoch = request->collected_at().millis_epoch() / 1000;
            }
            for (const auto& [plugin_name, data_bytes] : request->plugin_data()) {
                std::string json_str(data_bytes.begin(), data_bytes.end());
                inventory_store_->upsert(agent_id, plugin_name, json_str, collected_epoch);
            }
            spdlog::info("[gateway] ProxyInventory persisted for agent={}, plugins={}",
                          agent_id, request->plugin_data_size());
        } else {
            spdlog::info("[gateway] ProxyInventory received for agent={}, plugins={} "
                          "(inventory store not available)",
                          agent_id, request->plugin_data_size());
        }
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
            registry_.set_gateway_node(agent_id, request->gateway_node());
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

    // -- Status accessors for dashboard -----------------------------------------

    std::size_t session_count() const {
        std::lock_guard lock(sessions_mu_);
        return gateway_sessions_.size();
    }

private:
    AgentRegistry& registry_;
    EventBus& bus_;
    auth::AuthManager& auth_mgr_;
    auth::AutoApproveEngine& auto_approve_;
    yuzu::MetricsRegistry* metrics_{nullptr};
    AgentHealthStore* health_store_{nullptr};
    ManagementGroupStore* mgmt_group_store_{nullptr};
    InventoryStore* inventory_store_{nullptr};

    // Map of gateway session_id → agent_id for validation.
    mutable std::mutex sessions_mu_;
    std::unordered_map<std::string, std::string> gateway_sessions_;
};

// read_file_contents() and validate_key_file_permissions() live in file_utils.hpp

} // namespace detail

// -- ServerImpl ---------------------------------------------------------------

class ServerImpl final : public Server {
public:
    explicit ServerImpl(Config cfg, auth::AuthManager& auth_mgr)
        : cfg_(std::move(cfg)), auth_mgr_(auth_mgr), auto_approve_(), metrics_(), event_bus_(),
          registry_(event_bus_, metrics_),
          agent_service_(registry_, event_bus_, cfg_.tls_enabled && !cfg_.tls_ca_cert.empty(),
                         auth_mgr, auto_approve_, metrics_, cfg_.gateway_mode),
          api_rate_limiter_(cfg_.rate_limit),
          login_rate_limiter_(cfg_.login_rate_limit),
          mcp_rate_limiter_(std::max(cfg_.rate_limit / 5.0, 20.0)) {
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
        // Process health metrics (capability 22.1)
        metrics_.describe("yuzu_server_cpu_usage_percent",
                          "Server process CPU usage percentage", "gauge");
        metrics_.describe("yuzu_server_memory_bytes",
                          "Server process memory usage in bytes", "gauge");
        metrics_.describe("yuzu_server_open_connections",
                          "Number of connected gRPC agent streams", "gauge");
        metrics_.describe("yuzu_server_command_queue_depth",
                          "Number of in-flight command executions", "gauge");
        metrics_.describe("yuzu_server_uptime_seconds",
                          "Server process uptime in seconds", "gauge");

        // Wire health store into agent service
        agent_service_.set_health_store(&health_store_);

        // Create gateway upstream service if configured
        if (!cfg_.gateway_upstream_address.empty()) {
            gateway_service_ = std::make_unique<detail::GatewayUpstreamServiceImpl>(
                registry_, event_bus_, auth_mgr, auto_approve_, &metrics_, &health_store_);
        }

        // Create gateway management client for command forwarding
        if (!cfg_.gateway_command_address.empty()) {
            gw_mgmt_channel_ = grpc::CreateChannel(
                cfg_.gateway_command_address, grpc::InsecureChannelCredentials());
            gw_mgmt_stub_ = ::yuzu::server::v1::ManagementService::NewStub(gw_mgmt_channel_);
            spdlog::info("Gateway command forwarding enabled: {}", cfg_.gateway_command_address);
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
            oidc_cfg.skip_tls_verify = cfg_.oidc_skip_tls_verify;
            if (cfg_.oidc_skip_tls_verify)
                spdlog::warn("OIDC TLS certificate verification DISABLED — do not use in production");
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
        if (notification_store_)
            agent_service_.set_notification_store(notification_store_.get());
        if (webhook_store_)
            agent_service_.set_webhook_store(webhook_store_.get());
        if (inventory_store_)
            agent_service_.set_inventory_store(inventory_store_.get());

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

        // Phase 7: Runtime Configuration + Custom Properties
        {
            auto rtcfg_db = cfg_.auth_config_path.parent_path() / "runtime-config.db";
            runtime_config_store_ = std::make_unique<RuntimeConfigStore>(rtcfg_db);
            if (runtime_config_store_ && runtime_config_store_->is_open()) {
                // Apply stored overrides on startup
                apply_runtime_config_overrides();
            }
        }
        {
            auto props_db = cfg_.auth_config_path.parent_path() / "custom-properties.db";
            custom_properties_store_ = std::make_unique<CustomPropertiesStore>(props_db);
        }

        // Phase 7: Workflow Engine
        {
            auto wf_db = cfg_.auth_config_path.parent_path() / "workflows.db";
            workflow_engine_ = std::make_unique<WorkflowEngine>(wf_db);
            if (workflow_engine_ && workflow_engine_->is_open()) {
                spdlog::info("WorkflowEngine initialized at {}", wf_db.string());
            }
        }

        // Phase 7: Product Pack Store
        {
            auto pack_db = cfg_.auth_config_path.parent_path() / "product-packs.db";
            product_pack_store_ = std::make_unique<ProductPackStore>(pack_db);
            if (product_pack_store_ && product_pack_store_->is_open()) {
                spdlog::info("ProductPackStore initialized at {}", pack_db.string());
            }
        }

        // Notification & Webhook stores
        {
            auto notif_db = cfg_.auth_config_path.parent_path() / "notifications.db";
            notification_store_ = std::make_unique<NotificationStore>(notif_db);
        }
        {
            auto webhook_db = cfg_.auth_config_path.parent_path() / "webhooks.db";
            webhook_store_ = std::make_unique<WebhookStore>(webhook_db);
        }

        // Phase 7: Inventory Store (Issue 7.17)
        {
            auto inv_db = cfg_.auth_config_path.parent_path() / "inventory.db";
            inventory_store_ = std::make_unique<InventoryStore>(inv_db);
            if (inventory_store_ && inventory_store_->is_open()) {
                spdlog::info("InventoryStore initialized at {}", inv_db.string());
            }
            if (gateway_service_)
                gateway_service_->set_inventory_store(inventory_store_.get());
        }

        // Phase 7: Directory Sync (AD/Entra integration)
        {
            auto dirsync_db = cfg_.auth_config_path.parent_path() / "directory-sync.db";
            directory_sync_ = std::make_unique<DirectorySync>(dirsync_db);
            if (directory_sync_ && directory_sync_->is_open()) {
                spdlog::info("DirectorySync initialized at {}", dirsync_db.string());
            }
        }

        // Phase 7: Patch Manager
        {
            auto patch_db = cfg_.auth_config_path.parent_path() / "patches.db";
            patch_manager_ = std::make_unique<PatchManager>(patch_db);
            if (patch_manager_ && patch_manager_->is_open()) {
                spdlog::info("PatchManager initialized at {}", patch_db.string());
            }
        }

        // Phase 7: Deployment Jobs (Issue 7.7)
        {
            auto deploy_db = cfg_.auth_config_path.parent_path() / "deployment-jobs.db";
            deployment_store_ = std::make_unique<DeploymentStore>(deploy_db);
            if (deployment_store_ && deployment_store_->is_open()) {
                spdlog::info("DeploymentStore initialized at {}", deploy_db.string());
            }
        }

        // Phase 7: Device Discovery (Issue 7.18)
        {
            auto discovery_db = cfg_.auth_config_path.parent_path() / "discovery.db";
            discovery_store_ = std::make_unique<DiscoveryStore>(discovery_db);
            if (discovery_store_ && discovery_store_->is_open()) {
                spdlog::info("DiscoveryStore initialized at {}", discovery_db.string());
            }
        }

        // Phase 7: Software Deployment, Device Tokens, Licensing
        {
            auto sw_db = cfg_.auth_config_path.parent_path() / "software-deployments.db";
            sw_deploy_store_ = std::make_unique<SoftwareDeploymentStore>(sw_db);
        }
        {
            auto dt_db = cfg_.auth_config_path.parent_path() / "device-tokens.db";
            device_token_store_ = std::make_unique<DeviceTokenStore>(dt_db);
        }
        {
            auto lic_db = cfg_.auth_config_path.parent_path() / "license.db";
            license_store_ = std::make_unique<LicenseStore>(lic_db);
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
                    auto queue_depth = execution_tracker_
                        ? static_cast<double>(
                              execution_tracker_->query_executions({.status = "running"}).size())
                        : 0.0;
                    metrics_.gauge("yuzu_server_command_queue_depth").set(queue_depth);
                    auto uptime_s = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - server_start_time_).count();
                    metrics_.gauge("yuzu_server_uptime_seconds")
                        .set(static_cast<double>(uptime_s));
                }
            }
            spdlog::info("Fleet health recomputation thread stopped");
        });

        agent_server_->Wait();
    }

    void stop() noexcept override {
        // Guard against re-entrant calls from repeated signals.
        // The signal handler calls stop() directly, so a second Ctrl+C
        // re-enters stop() on a different thread while the first is still
        // joining threads — causing "Resource deadlock avoided".
        bool expected = false;
        if (!stop_entered_.compare_exchange_strong(expected, true,
                                                   std::memory_order_acq_rel)) {
            return;  // Another thread is already running stop()
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

        // Release Phase 2 components before closing shared DB
        execution_tracker_.reset();
        approval_manager_.reset();
        schedule_engine_.reset();
        if (shared_instr_db_) {
            sqlite3_close(shared_instr_db_);
            shared_instr_db_ = nullptr;
        }

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
        synth.auth_source = api_token.mcp_tier.empty() ? "api_token" : "mcp_token";
        synth.token_scope_service = api_token.scope_service;
        synth.mcp_tier = api_token.mcp_tier;

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
        res.set_content(R"({"error":{"code":401,"message":"unauthorized"},"meta":{"api_version":"v1"}})", "application/json");
        return std::nullopt;
    }

    bool require_admin(const httplib::Request& req, httplib::Response& res) {
        auto session = require_auth(req, res);
        if (!session)
            return false;
        if (session->role != auth::Role::admin) {
            res.status = 403;
            res.set_content(R"({"error":{"code":403,"message":"admin role required"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":403,"message":"service-scoped tokens require RBAC to be enabled"},"meta":{"api_version":"v1"}})",
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
            res.set_content(R"({"error":{"code":403,"message":"admin role required"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":403,"message":"service-scoped tokens require RBAC to be enabled"},"meta":{"api_version":"v1"}})",
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
            res.set_content(R"({"error":{"code":403,"message":"admin role required"},"meta":{"api_version":"v1"}})", "application/json");
            return false;
        }
        return true;
    }

    /// Return the agent list as JSON, filtered by RBAC visibility for the given user.
    nlohmann::json get_visible_agents_json(const std::string& username) {
        auto agents = registry_.to_json_obj();
        if (rbac_store_ && rbac_store_->is_rbac_enabled() && mgmt_group_store_) {
            bool global_read =
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
                std::thread([stub, svc, gp = std::move(gp)]() {
                    ::yuzu::server::v1::SendCommandRequest req;
                    req.add_agent_ids(gp.agent_id);
                    *req.mutable_command() = gp.cmd;
                    req.set_timeout_seconds(300);

                    grpc::ClientContext ctx;
                    ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(300));
                    auto reader = stub->SendCommand(&ctx, req);

                    ::yuzu::server::v1::SendCommandResponse resp;
                    while (reader->Read(&resp)) {
                        svc->process_gateway_response(resp.agent_id(), resp.response());
                    }
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
            forward_gateway_pending();
        }
    }

    // -- HTML fragment renderers for HTMX Settings page -------------------------

    // -- Server Configuration fragment ----------------------------------------

    std::string render_server_config_fragment() {
        std::string html;

        html += "<table class=\"user-table\" style=\"font-size:0.8rem\">"
                "<thead><tr><th>Setting</th><th>Value</th></tr></thead>"
                "<tbody>";

        // Network listeners
        html += "<tr><td>Agent gRPC Address</td><td><code>" +
                html_escape(cfg_.listen_address) + "</code></td></tr>";
        html += "<tr><td>Management gRPC Address</td><td><code>" +
                html_escape(cfg_.management_address) + "</code></td></tr>";
        html += "<tr><td>Web UI Address</td><td><code>" +
                html_escape(cfg_.web_address) + "</code></td></tr>";
        html += "<tr><td>Web UI Port</td><td><code>" +
                std::to_string(cfg_.web_port) + "</code></td></tr>";

        // Session management
        html += "<tr><td>Session Timeout</td><td><code>" +
                std::to_string(cfg_.session_timeout.count()) + "s</code></td></tr>";
        html += "<tr><td>Max Agents</td><td><code>" +
                std::to_string(cfg_.max_agents) + "</code></td></tr>";

        // Authentication
        std::string auth_path_str = cfg_.auth_config_path.empty()
            ? std::string("(default)")
            : html_escape(cfg_.auth_config_path.string());
        html += "<tr><td>Auth Config Path</td><td><span class=\"file-name\">" +
                auth_path_str + "</span></td></tr>";

        // Rate limiting
        html += "<tr><td>API Rate Limit</td><td><code>" +
                std::to_string(cfg_.rate_limit) + "</code> req/s per IP</td></tr>";
        html += "<tr><td>Login Rate Limit</td><td><code>" +
                std::to_string(cfg_.login_rate_limit) + "</code> req/s per IP</td></tr>";

        html += "</tbody></table>";
        return html;
    }

    // -- TLS fragment ---------------------------------------------------------

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

        std::string html = "<form id=\"tls-form\">"
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
               "      <details style=\"margin-top:0.5rem\">"
               "        <summary class=\"btn btn-secondary\" "
               "          style=\"cursor:pointer;display:inline-block\">Paste PEM</summary>"
               "        <form hx-post=\"/api/settings/cert-paste\" "
               "              hx-target=\"#tls-section\" hx-swap=\"innerHTML\" "
               "              style=\"margin-top:0.5rem\">"
               "          <input type=\"hidden\" name=\"type\" value=\"cert\">"
               "          <textarea name=\"content\" "
               "            style=\"width:100%;min-height:150px;font-family:monospace;"
               "                   font-size:0.75rem;background:var(--bg);color:var(--fg);"
               "                   border:1px solid var(--border);border-radius:4px;"
               "                   padding:0.5rem;resize:vertical\" "
               "            placeholder=\"-----BEGIN CERTIFICATE-----&#10;...paste PEM content...&#10;"
               "-----END CERTIFICATE-----\"></textarea>"
               "          <button type=\"submit\" class=\"btn btn-primary\" "
               "            style=\"margin-top:0.5rem\">Save</button>"
               "        </form>"
               "      </details>"
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
               "      <details style=\"margin-top:0.5rem\">"
               "        <summary class=\"btn btn-secondary\" "
               "          style=\"cursor:pointer;display:inline-block\">Paste PEM</summary>"
               "        <form hx-post=\"/api/settings/cert-paste\" "
               "              hx-target=\"#tls-section\" hx-swap=\"innerHTML\" "
               "              style=\"margin-top:0.5rem\">"
               "          <input type=\"hidden\" name=\"type\" value=\"key\">"
               "          <textarea name=\"content\" "
               "            style=\"width:100%;min-height:150px;font-family:monospace;"
               "                   font-size:0.75rem;background:var(--bg);color:var(--fg);"
               "                   border:1px solid var(--border);border-radius:4px;"
               "                   padding:0.5rem;resize:vertical\" "
               "            placeholder=\"-----BEGIN PRIVATE KEY-----&#10;...paste PEM content...&#10;"
               "-----END PRIVATE KEY-----\"></textarea>"
               "          <button type=\"submit\" class=\"btn btn-primary\" "
               "            style=\"margin-top:0.5rem\">Save</button>"
               "        </form>"
               "      </details>"
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
               "      <details style=\"margin-top:0.5rem\">"
               "        <summary class=\"btn btn-secondary\" "
               "          style=\"cursor:pointer;display:inline-block\">Paste PEM</summary>"
               "        <form hx-post=\"/api/settings/cert-paste\" "
               "              hx-target=\"#tls-section\" hx-swap=\"innerHTML\" "
               "              style=\"margin-top:0.5rem\">"
               "          <input type=\"hidden\" name=\"type\" value=\"ca\">"
               "          <textarea name=\"content\" "
               "            style=\"width:100%;min-height:150px;font-family:monospace;"
               "                   font-size:0.75rem;background:var(--bg);color:var(--fg);"
               "                   border:1px solid var(--border);border-radius:4px;"
               "                   padding:0.5rem;resize:vertical\" "
               "            placeholder=\"-----BEGIN CERTIFICATE-----&#10;...paste PEM content...&#10;"
               "-----END CERTIFICATE-----\"></textarea>"
               "          <button type=\"submit\" class=\"btn btn-primary\" "
               "            style=\"margin-top:0.5rem\">Save</button>"
               "        </form>"
               "      </details>"
               "    </div>"
               "  </div>"
               "</div>"
               "</form>";

        // One-way TLS
        std::string owt_color = cfg_.allow_one_way_tls ? "#f0883e" : "#8b949e";
        std::string owt_text = cfg_.allow_one_way_tls ? "Enabled (no client cert required)" : "Disabled (mTLS enforced)";
        html += "<div class=\"form-row\" style=\"margin-top:0.75rem\">"
                "  <label>One-Way TLS</label>"
                "  <span style=\"font-size:0.8rem;color:" + owt_color + "\">" + owt_text + "</span>"
                "</div>";

        // Management TLS overrides
        std::string mgmt_cert = cfg_.mgmt_tls_server_cert.empty() ? "Using agent TLS" : html_escape(cfg_.mgmt_tls_server_cert.string());
        std::string mgmt_key = cfg_.mgmt_tls_server_key.empty() ? "Using agent TLS" : html_escape(cfg_.mgmt_tls_server_key.string());
        std::string mgmt_ca = cfg_.mgmt_tls_ca_cert.empty() ? "Using agent TLS" : html_escape(cfg_.mgmt_tls_ca_cert.string());

        html += "<div style=\"margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border)\">"
                "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
                "margin-bottom:0.5rem;text-transform:uppercase;letter-spacing:0.05em\">"
                "Management Listener TLS Override</div>"
                "<div class=\"form-row\">"
                "  <label>Mgmt Certificate</label>"
                "  <span class=\"file-name\">" + mgmt_cert + "</span>"
                "</div>"
                "<div class=\"form-row\">"
                "  <label>Mgmt Private Key</label>"
                "  <span class=\"file-name\">" + mgmt_key + "</span>"
                "</div>"
                "<div class=\"form-row\">"
                "  <label>Mgmt CA Cert</label>"
                "  <span class=\"file-name\">" + mgmt_ca + "</span>"
                "</div>"
                "</div>";

        html += "<div class=\"feedback\" id=\"tls-feedback\"></div>";
        return html;
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
                           "  <thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Owner</th>"
                           "  <th>Created</th><th>Expires</th><th>Last Used</th>"
                           "  <th>Status</th><th></th></tr></thead>"
                           "  <tbody>";

        if (tokens.empty()) {
            html += "<tr><td colspan=\"9\" style=\"color:#484f58\">No API tokens created</td></tr>";
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

                // Determine type badge
                std::string type_text = t.mcp_tier.empty() ? "API" : "MCP";
                std::string type_detail = t.mcp_tier.empty() ? "" : " (" + html_escape(t.mcp_tier) + ")";
                std::string type_color = t.mcp_tier.empty() ? "#484f58" : "#8957e5";

                html += "<tr><td><code>" + html_escape(t.token_id) +
                        "</code></td>"
                        "<td>" +
                        html_escape(t.name) +
                        "</td>"
                        "<td><span class=\"role-badge\" style=\"background:" + type_color + ";color:#fff\">" +
                        type_text + "</span>" + type_detail +
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
                "  <div class=\"mini-field\">"
                "    <label>MCP Tier</label>"
                "    <select name=\"mcp_tier\" style=\"width:120px\">"
                "      <option value=\"\">(none — API)</option>"
                "      <option value=\"readonly\">readonly</option>"
                "      <option value=\"operator\">operator</option>"
                "      <option value=\"supervised\">supervised</option>"
                "    </select>"
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
        std::string html;

        // Show OTA config values
        std::string ota_color = cfg_.ota_enabled ? "#3fb950" : "#484f58";
        std::string ota_text = cfg_.ota_enabled ? "Enabled" : "Disabled";
        html += "<div class=\"form-row\">"
                "  <label>OTA Updates</label>"
                "  <span style=\"font-size:0.8rem;color:" + ota_color + ";font-weight:600\">" +
                ota_text + "</span>"
                "</div>";

        std::string update_dir_str = cfg_.update_dir.empty()
            ? std::string("(default)")
            : html_escape(cfg_.update_dir.string());
        html += "<div class=\"form-row\" style=\"margin-bottom:1rem\">"
                "  <label>Update Directory</label>"
                "  <span class=\"file-name\">" + update_dir_str + "</span>"
                "</div>";

        if (!update_registry_) {
            html += "<span style=\"color:#484f58\">OTA updates are disabled "
                    "(start server with <code>--ota-enabled</code>).</span>";
            return html;
        }

        auto packages = update_registry_->list_packages();

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

    // -- Gateway fragment renderer --------------------------------------------

    std::string render_gateway_fragment() {
        bool enabled = gateway_service_ != nullptr;
        std::string status_color = enabled ? "#3fb950" : "#484f58";
        std::string status_text = enabled ? "Enabled" : "Disabled";

        std::string html;

        // Status row
        html += "<div class=\"form-row\">"
                "  <label>Upstream Service</label>"
                "  <span style=\"font-size:0.8rem;color:" + status_color + ";font-weight:600\">" +
                status_text + "</span>"
                "</div>";

        if (enabled) {
            // Address
            html += "<div class=\"form-row\">"
                    "  <label>Listen Address</label>"
                    "  <code style=\"font-size:0.8rem\">" +
                    html_escape(cfg_.gateway_upstream_address) +
                    "</code>"
                    "</div>";

            // Gateway mode
            html += "<div class=\"form-row\">"
                    "  <label>Gateway Mode</label>"
                    "  <span style=\"font-size:0.8rem;color:" +
                    std::string(cfg_.gateway_mode ? "#3fb950" : "#8b949e") + "\">" +
                    (cfg_.gateway_mode ? "Active" : "Inactive") +
                    "</span>"
                    "</div>";

            // Active sessions
            auto count = gateway_service_->session_count();
            html += "<div class=\"form-row\">"
                    "  <label>Active Sessions</label>"
                    "  <span style=\"font-size:0.8rem\">" + std::to_string(count) +
                    " agent" + (count != 1 ? "s" : "") + " via gateway</span>"
                    "</div>";
        } else {
            html += "<p style=\"font-size:0.75rem;color:#8b949e;margin-top:0.5rem\">"
                    "The gateway upstream service is not running. Start the server with "
                    "<code>--gateway-upstream 0.0.0.0:50055</code> to enable it.</p>";
        }

        // Environment variable reference
        html += "<div style=\"margin-top:1rem;padding-top:0.75rem;border-top:1px solid var(--border)\">"
                "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
                "margin-bottom:0.5rem;text-transform:uppercase;letter-spacing:0.05em\">"
                "Erlang Gateway Environment Variables</div>"
                "<table class=\"user-table\" style=\"font-size:0.75rem\">"
                "<thead><tr><th>Variable</th><th>Description</th><th>Default</th></tr></thead>"
                "<tbody>"
                "<tr><td><code>YUZU_GW_UPSTREAM_ADDR</code></td>"
                "    <td>C++ server hostname</td><td><code>127.0.0.1</code></td></tr>"
                "<tr><td><code>YUZU_GW_UPSTREAM_PORT</code></td>"
                "    <td>C++ server port</td><td><code>50055</code></td></tr>"
                "<tr><td><code>YUZU_GW_AGENT_PORT</code></td>"
                "    <td>Agent-facing listener port</td><td><code>50051</code></td></tr>"
                "<tr><td><code>YUZU_GW_MGMT_PORT</code></td>"
                "    <td>Management listener port</td><td><code>50052</code></td></tr>"
                "<tr><td><code>YUZU_GW_TLS_ENABLED</code></td>"
                "    <td>TLS master switch</td><td><code>auto</code></td></tr>"
                "<tr><td><code>YUZU_GW_TLS_CERTFILE</code></td>"
                "    <td>Gateway certificate path</td><td>&mdash;</td></tr>"
                "<tr><td><code>YUZU_GW_TLS_KEYFILE</code></td>"
                "    <td>Gateway private key path</td><td>&mdash;</td></tr>"
                "<tr><td><code>YUZU_GW_TLS_CACERTFILE</code></td>"
                "    <td>CA certificate bundle</td><td>&mdash;</td></tr>"
                "<tr><td><code>YUZU_GW_PROMETHEUS_PORT</code></td>"
                "    <td>Prometheus metrics port</td><td><code>9568</code></td></tr>"
                "<tr><td><code>YUZU_GW_HEALTH_PORT</code></td>"
                "    <td>Health endpoint port</td><td><code>8080</code></td></tr>"
                "</tbody></table>"
                "</div>";

        return html;
    }

    // -- HTTPS Dashboard fragment renderer ------------------------------------

    std::string render_https_fragment() {
        std::string html;

        std::string status_color = cfg_.https_enabled ? "#3fb950" : "#484f58";
        std::string status_text = cfg_.https_enabled ? "Enabled" : "Disabled";

        html += "<div class=\"form-row\">"
                "  <label>HTTPS</label>"
                "  <span style=\"font-size:0.8rem;color:" + status_color + ";font-weight:600\">" +
                status_text + "</span>"
                "</div>";

        html += "<div class=\"form-row\">"
                "  <label>HTTPS Port</label>"
                "  <code style=\"font-size:0.8rem\">" + std::to_string(cfg_.https_port) + "</code>"
                "</div>";

        std::string https_cert = cfg_.https_cert_path.empty() ? "Not configured" : html_escape(cfg_.https_cert_path.string());
        std::string https_key = cfg_.https_key_path.empty() ? "Not configured" : html_escape(cfg_.https_key_path.string());

        html += "<div class=\"form-row\">"
                "  <label>Certificate</label>"
                "  <span class=\"file-name\">" + https_cert + "</span>"
                "</div>";
        html += "<div class=\"form-row\">"
                "  <label>Private Key</label>"
                "  <span class=\"file-name\">" + https_key + "</span>"
                "</div>";

        std::string redir_color = cfg_.https_redirect ? "#3fb950" : "#8b949e";
        std::string redir_text = cfg_.https_redirect ? "Enabled" : "Disabled";
        html += "<div class=\"form-row\">"
                "  <label>HTTP Redirect</label>"
                "  <span style=\"font-size:0.8rem;color:" + redir_color + "\">" + redir_text + "</span>"
                "</div>";

        if (!cfg_.https_enabled) {
            html += "<p style=\"font-size:0.75rem;color:#8b949e;margin-top:0.5rem\">"
                    "Start the server with <code>--https --https-cert &lt;path&gt; --https-key &lt;path&gt;</code> to enable.</p>";
        }

        return html;
    }

    // -- Analytics fragment renderer ------------------------------------------

    std::string render_analytics_fragment() {
        std::string html;

        std::string status_color = cfg_.analytics_enabled ? "#3fb950" : "#484f58";
        std::string status_text = cfg_.analytics_enabled ? "Enabled" : "Disabled";

        html += "<div class=\"form-row\">"
                "  <label>Analytics</label>"
                "  <span style=\"font-size:0.8rem;color:" + status_color + ";font-weight:600\">" +
                status_text + "</span>"
                "</div>";

        html += "<div class=\"form-row\">"
                "  <label>Drain Interval</label>"
                "  <code style=\"font-size:0.8rem\">" +
                std::to_string(cfg_.analytics_drain_interval_seconds) + "s</code>"
                "</div>";

        html += "<div class=\"form-row\">"
                "  <label>Batch Size</label>"
                "  <code style=\"font-size:0.8rem\">" +
                std::to_string(cfg_.analytics_batch_size) + "</code>"
                "</div>";

        // ClickHouse
        bool ch_configured = !cfg_.clickhouse_url.empty();
        std::string ch_color = ch_configured ? "#3fb950" : "#484f58";
        std::string ch_text = ch_configured ? html_escape(cfg_.clickhouse_url) : "Not configured";

        html += "<div style=\"margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border)\">"
                "<div style=\"font-size:0.7rem;color:#8b949e;font-weight:600;"
                "margin-bottom:0.5rem;text-transform:uppercase;letter-spacing:0.05em\">"
                "ClickHouse Integration</div>";
        html += "<div class=\"form-row\">"
                "  <label>URL</label>"
                "  <span style=\"font-size:0.8rem;color:" + ch_color + "\">" + ch_text + "</span>"
                "</div>";
        if (ch_configured) {
            html += "<div class=\"form-row\">"
                    "  <label>Database</label>"
                    "  <code style=\"font-size:0.8rem\">" + html_escape(cfg_.clickhouse_database) + "</code>"
                    "</div>";
            html += "<div class=\"form-row\">"
                    "  <label>Table</label>"
                    "  <code style=\"font-size:0.8rem\">" + html_escape(cfg_.clickhouse_table) + "</code>"
                    "</div>";
            html += "<div class=\"form-row\">"
                    "  <label>Username</label>"
                    "  <code style=\"font-size:0.8rem\">" +
                    (cfg_.clickhouse_username.empty() ? std::string("(default)") : html_escape(cfg_.clickhouse_username)) +
                    "</code></div>";
            html += "<div class=\"form-row\">"
                    "  <label>Password</label>"
                    "  <span style=\"font-size:0.8rem;color:#8b949e\">" +
                    (cfg_.clickhouse_password.empty() ? std::string("(not set)") : std::string("********")) +
                    "</span></div>";
        }
        html += "</div>";

        // JSONL export
        std::string jsonl_path = cfg_.analytics_jsonl_path.empty() ? "Not configured" : html_escape(cfg_.analytics_jsonl_path.string());
        html += "<div class=\"form-row\" style=\"margin-top:0.5rem\">"
                "  <label>JSONL Export</label>"
                "  <span class=\"file-name\">" + jsonl_path + "</span>"
                "</div>";

        return html;
    }

    // -- Data Retention fragment renderer -------------------------------------

    std::string render_data_retention_fragment() {
        std::string html;

        html += "<div class=\"form-row\">"
                "  <label>Response Data</label>"
                "  <code style=\"font-size:0.8rem\">" +
                std::to_string(cfg_.response_retention_days) + " days</code>"
                "</div>";

        html += "<div class=\"form-row\">"
                "  <label>Audit Logs</label>"
                "  <code style=\"font-size:0.8rem\">" +
                std::to_string(cfg_.audit_retention_days) + " days</code>"
                "</div>";

        return html;
    }

    // -- MCP (AI Integration) fragment renderer --------------------------------

    std::string render_mcp_fragment() {
        std::string html;
        bool mcp_enabled = !cfg_.mcp_disable;

        std::string status_color = mcp_enabled ? "#3fb950" : "#484f58";
        std::string status_text = mcp_enabled ? "Enabled" : "Disabled";

        html += "<div class=\"form-row\">"
                "  <label>Status</label>"
                "  <span style=\"font-size:0.8rem;color:" + status_color + ";font-weight:600\">" +
                status_text + "</span>"
                "</div>";

        html += "<div class=\"form-row\">"
                "  <label>Endpoint</label>"
                "  <code style=\"font-size:0.8rem\">POST /mcp/v1/</code>"
                "</div>";

        // MCP Enabled toggle
        std::string enabled_checked = mcp_enabled ? " checked" : "";
        html += "<form hx-post=\"/api/settings/mcp\" hx-target=\"#mcp-section\" hx-swap=\"innerHTML\">"
                "<div class=\"form-row\">"
                "  <label>MCP Enabled</label>"
                "  <label class=\"toggle\">"
                "    <input type=\"hidden\" name=\"enabled\" value=\"false\">"
                "    <input type=\"checkbox\" name=\"enabled\" value=\"true\"" +
                enabled_checked + " hx-post=\"/api/settings/mcp\" hx-target=\"#mcp-section\""
                " hx-swap=\"innerHTML\" hx-include=\"closest form\">"
                "    <span class=\"slider\"></span>"
                "  </label>"
                "</div>";

        // Read-Only Mode toggle
        std::string readonly_checked = cfg_.mcp_read_only ? " checked" : "";
        std::string readonly_color = cfg_.mcp_read_only ? "#d29922" : "#484f58";
        std::string readonly_text = cfg_.mcp_read_only ? "Read-Only" : "Full Access";
        html += "<div class=\"form-row\">"
                "  <label>Access Mode</label>"
                "  <label class=\"toggle\">"
                "    <input type=\"hidden\" name=\"read_only\" value=\"false\">"
                "    <input type=\"checkbox\" name=\"read_only\" value=\"true\"" +
                readonly_checked + " hx-post=\"/api/settings/mcp\" hx-target=\"#mcp-section\""
                " hx-swap=\"innerHTML\" hx-include=\"closest form\">"
                "    <span class=\"slider\"></span>"
                "  </label>"
                "  <span style=\"font-size:0.75rem;color:" + readonly_color +
                ";margin-left:0.5rem\">" + readonly_text + "</span>"
                "</div>";

        html += "</form>";

        html += "<p style=\"font-size:0.7rem;color:#484f58;margin-top:0.75rem\">"
                "MCP authentication uses API Tokens with an MCP tier. "
                "Create tokens in the <strong>API Tokens</strong> section above — "
                "select an MCP tier (readonly, operator, or supervised) from the dropdown."
                "</p>";

        // Connection quick-start
        std::string proto = cfg_.https_enabled ? "https" : "http";
        std::string host = cfg_.web_address == "0.0.0.0" ? "localhost" : cfg_.web_address;
        auto port = cfg_.https_enabled ? cfg_.https_port : cfg_.web_port;
        std::string url = proto + "://" + host + ":" + std::to_string(port) + "/mcp/v1/";

        html += "<div style=\"margin-top:0.75rem;padding:0.75rem;background:#0d1117;"
                "border:1px solid var(--border);border-radius:0.3rem\">"
                "  <div style=\"font-size:0.7rem;color:#8b949e;margin-bottom:0.3rem;"
                "font-weight:600\">MCP CLIENT CONNECTION</div>"
                "  <div style=\"font-size:0.75rem;margin-bottom:0.3rem\">"
                "    Endpoint: <code>" + html_escape(url) + "</code></div>"
                "  <div style=\"font-size:0.7rem;color:#484f58\">"
                "    Transport: HTTP + JSON-RPC 2.0 &nbsp;|&nbsp; "
                "    Auth: <code>Authorization: Bearer &lt;mcp-token&gt;</code>"
                "  </div>"
                "</div>";

        return html;
    }

    // -- Vulnerability Management (NVD) fragment renderer ---------------------

    std::string render_nvd_fragment() {
        std::string html;

        std::string status_color = cfg_.nvd_sync_enabled ? "#3fb950" : "#484f58";
        std::string status_text = cfg_.nvd_sync_enabled ? "Enabled" : "Disabled";

        html += "<div class=\"form-row\">"
                "  <label>NVD Sync</label>"
                "  <span style=\"font-size:0.8rem;color:" + status_color + ";font-weight:600\">" +
                status_text + "</span>"
                "</div>";

        html += "<div class=\"form-row\">"
                "  <label>Sync Interval</label>"
                "  <code style=\"font-size:0.8rem\">" +
                std::to_string(cfg_.nvd_sync_interval.count() / 3600) + " hours</code>"
                "</div>";

        html += "<div class=\"form-row\">"
                "  <label>API Key</label>"
                "  <span style=\"font-size:0.8rem;color:#8b949e\">" +
                (cfg_.nvd_api_key.empty() ? std::string("Not configured (lower rate limits)") : std::string("Configured")) +
                "</span></div>";

        html += "<div class=\"form-row\">"
                "  <label>HTTP Proxy</label>"
                "  <span style=\"font-size:0.8rem\">" +
                (cfg_.nvd_proxy.empty() ? std::string("<span style=\"color:#8b949e\">None</span>") : std::string("<code>") + html_escape(cfg_.nvd_proxy) + "</code>") +
                "</span></div>";

        if (!cfg_.nvd_sync_enabled) {
            html += "<p style=\"font-size:0.75rem;color:#8b949e;margin-top:0.5rem\">"
                    "Start the server without <code>--no-nvd-sync</code> to enable CVE feed synchronization.</p>";
        }

        return html;
    }

    // -- Directory / OIDC fragment renderer ------------------------------------

    std::string render_directory_fragment() {
        std::string html;

        bool oidc_configured = !cfg_.oidc_issuer.empty() && !cfg_.oidc_client_id.empty();

        // Status badge
        if (oidc_configured) {
            html += "<div style=\"margin-bottom:1rem\">"
                    "  <span style=\"font-size:0.75rem;background:#238636;color:#fff;"
                    "padding:0.2rem 0.6rem;border-radius:4px;font-weight:600\">"
                    "Configured</span>"
                    "</div>";
        } else {
            html += "<div style=\"margin-bottom:1rem\">"
                    "  <span style=\"font-size:0.75rem;background:#9e6a03;color:#fff;"
                    "padding:0.2rem 0.6rem;border-radius:4px;font-weight:600\">"
                    "Not configured</span>"
                    "</div>";
        }

        // Editable OIDC form
        html += "<form hx-post=\"/api/settings/oidc\" "
                "hx-target=\"#directory-section\" hx-swap=\"innerHTML\">";

        // Issuer URL
        html += "<div class=\"form-row\">"
                "  <label style=\"min-width:140px\">Issuer URL</label>"
                "  <input type=\"text\" name=\"issuer\" "
                "value=\"" + html_escape(cfg_.oidc_issuer) + "\" "
                "placeholder=\"https://login.microsoftonline.com/{tenant}/v2.0\" "
                "style=\"flex:1;min-width:0\">"
                "</div>";

        // Client ID
        html += "<div class=\"form-row\">"
                "  <label style=\"min-width:140px\">Client ID</label>"
                "  <input type=\"text\" name=\"client_id\" "
                "value=\"" + html_escape(cfg_.oidc_client_id) + "\" "
                "placeholder=\"Application (client) ID from Azure portal\" "
                "style=\"flex:1;min-width:0\">"
                "</div>";

        // Client Secret (password field — show placeholder if already set)
        html += "<div class=\"form-row\">"
                "  <label style=\"min-width:140px\">Client Secret</label>"
                "  <input type=\"password\" name=\"client_secret\" "
                "value=\"\" "
                "placeholder=\"" +
                (cfg_.oidc_client_secret.empty()
                     ? std::string("Client secret value")
                     : std::string("********")) +
                "\" "
                "style=\"flex:1;min-width:0\">"
                "</div>";

        // Redirect URI
        html += "<div class=\"form-row\">"
                "  <label style=\"min-width:140px\">Redirect URI</label>"
                "  <input type=\"text\" name=\"redirect_uri\" "
                "value=\"" + html_escape(cfg_.oidc_redirect_uri) + "\" "
                "placeholder=\"(auto-computed from web address)\" "
                "style=\"flex:1;min-width:0\">"
                "</div>";

        // Admin Group ID
        html += "<div class=\"form-row\">"
                "  <label style=\"min-width:140px\">Admin Group ID</label>"
                "  <input type=\"text\" name=\"admin_group\" "
                "value=\"" + html_escape(cfg_.oidc_admin_group) + "\" "
                "placeholder=\"Entra group object ID for admin role mapping\" "
                "style=\"flex:1;min-width:0\">"
                "</div>";

        // Skip TLS Verify (toggle checkbox)
        std::string tls_checked = cfg_.oidc_skip_tls_verify ? " checked" : "";
        html += "<div class=\"form-row\">"
                "  <label style=\"min-width:140px\">Skip TLS Verify</label>"
                "  <label class=\"toggle\">"
                "    <input type=\"checkbox\" name=\"skip_tls_verify\" value=\"true\"" +
                tls_checked +
                ">"
                "    <span class=\"slider\"></span>"
                "  </label>"
                "  <span style=\"font-size:0.7rem;color:#f85149;margin-left:0.5rem\">"
                "Insecure — dev only</span>"
                "</div>";

        // Buttons row
        html += "<div style=\"margin-top:1rem;display:flex;gap:0.75rem;align-items:center\">"
                "  <button class=\"btn btn-primary\" type=\"submit\">Save OIDC Configuration</button>"
                "  <button class=\"btn btn-secondary\" type=\"button\" "
                "hx-post=\"/api/settings/oidc/test\" "
                "hx-target=\"#oidc-feedback\" hx-swap=\"innerHTML\" "
                "hx-include=\"closest form\">Test Connection</button>"
                "</div>";

        html += "</form>";

        // Feedback div
        html += "<div class=\"feedback\" id=\"oidc-feedback\"></div>";

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

        // -- Auth middleware (pre-routing) -----------------------------------
        web_server_->set_pre_routing_handler(
            [this](const httplib::Request& req,
                   httplib::Response& res) -> httplib::Server::HandlerResponse {
                // Lightweight probes — always allowed, no auth, no rate limit
                if (req.path == "/livez" || req.path == "/readyz") {
                    return httplib::Server::HandlerResponse::Unhandled;
                }

                // Rate limiting — separate buckets for login, MCP, and general API (G4-UHP-MCP-008)
                bool is_login = (req.path == "/login" && req.method == "POST");
                bool is_mcp = req.path.starts_with("/mcp/");
                auto& limiter = is_login ? login_rate_limiter_
                              : is_mcp   ? mcp_rate_limiter_
                              :            api_rate_limiter_;
                if (!limiter.allow(req.remote_addr)) {
                    res.status = 429;
                    res.set_header("Retry-After", "1");
                    res.set_content(R"({"error":{"code":429,"message":"rate limit exceeded"},"meta":{"api_version":"v1"}})", "application/json");
                    return httplib::Server::HandlerResponse::Handled;
                }

                // CSRF protection: reject state-changing requests from foreign origins
                // when authenticated via session cookie (G2-SEC-B1-005).
                // API token auth (Bearer/X-Yuzu-Token) is naturally CSRF-immune.
                if (req.method == "POST" || req.method == "PUT" || req.method == "DELETE") {
                    auto origin = req.get_header_value("Origin");
                    if (!origin.empty()) {
                        auto scheme = cfg_.https_enabled ? "https" : "http";
                        auto port = cfg_.https_enabled ? cfg_.https_port : cfg_.web_port;
                        auto self1 = std::format("{}://{}:{}", scheme, cfg_.web_address, port);
                        auto self2 = std::format("{}://localhost:{}", scheme, port);
                        auto self3 = std::format("{}://127.0.0.1:{}", scheme, port);
                        if (origin != self1 && origin != self2 && origin != self3) {
                            // Foreign origin + no Bearer token = CSRF attempt
                            auto bearer = req.get_header_value("Authorization");
                            auto yuzu_tok = req.get_header_value("X-Yuzu-Token");
                            if (bearer.empty() && yuzu_tok.empty()) {
                                res.status = 403;
                                res.set_content(R"({"error":{"code":403,"message":"CSRF: origin mismatch"},"meta":{"api_version":"v1"}})",
                                                "application/json");
                                return httplib::Server::HandlerResponse::Handled;
                            }
                        }
                    }
                }

                // Allow unauthenticated access to login page, health, OIDC flow, and OpenAPI spec
                if (req.path == "/login" || req.path == "/health" ||
                    req.path == "/auth/oidc/start" || req.path == "/auth/callback" ||
                    req.path == "/api/v1/openapi.json" ||
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

                // Check session cookie
                auto token = extract_session_cookie(req);
                auto session = auth_mgr_.validate_session(token);

                // If no session cookie, try API token auth (Bearer or X-Yuzu-Token)
                if (!session && api_token_store_) {
                    auto auth_header = req.get_header_value("Authorization");
                    if (auth_header.size() > 7 && auth_header.substr(0, 7) == "Bearer ") {
                        auto api_token = api_token_store_->validate_token(auth_header.substr(7));
                        if (api_token) session = synthesize_token_session(*api_token);
                    }
                    if (!session) {
                        auto custom_header = req.get_header_value("X-Yuzu-Token");
                        if (!custom_header.empty()) {
                            auto api_token = api_token_store_->validate_token(custom_header);
                            if (api_token) session = synthesize_token_session(*api_token);
                        }
                    }
                }

                if (!session) {
                    // API calls and MCP endpoint get 401 JSON, pages get redirect
                    if (req.path.starts_with("/api/") || req.path == "/events" ||
                        req.path.starts_with("/mcp/")) {
                        res.status = 401;
                        res.set_content(R"({"error":{"code":401,"message":"unauthorized"},"meta":{"api_version":"v1"}})", "application/json");
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
            std::shared_lock oidc_lock(oidc_mu_);
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
                res.set_content(R"({"error":{"code":401,"message":"Invalid username or password"},"meta":{"api_version":"v1"}})", "application/json");
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
            // HTMX clients get a redirect header; non-HTMX get JSON
            if (!req.get_header_value("HX-Request").empty()) {
                res.set_header("HX-Redirect", "/login");
                res.set_content("", "text/plain");
            } else {
                res.set_content(R"({"status":"ok"})", "application/json");
            }
        });

        // -- OIDC SSO endpoints -----------------------------------------------
        web_server_->Get(
            "/auth/oidc/start", [this](const httplib::Request& req, httplib::Response& res) {
                std::shared_lock oidc_lock(oidc_mu_);
                if (!oidc_provider_ || !oidc_provider_->is_enabled()) {
                    res.status = 404;
                    res.set_content(R"({"error":{"code":404,"message":"OIDC not configured"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }
                // Use the configured redirect URI only — never derive from the
                // Host header, which can be manipulated for phishing attacks (M3).
                if (cfg_.oidc_redirect_uri.empty()) {
                    res.status = 500;
                    res.set_content(R"({"error":{"code":500,"message":"OIDC redirect_uri not configured — set --oidc-redirect-uri or YUZU_OIDC_REDIRECT_URI"},"meta":{"api_version":"v1"}})",
                                    "application/json");
                    spdlog::error("OIDC auth flow blocked: redirect_uri not configured");
                    return;
                }
                auto auth_url = oidc_provider_->start_auth_flow(cfg_.oidc_redirect_uri);
                res.set_redirect(auth_url);
            });

        web_server_->Get("/auth/callback", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
            std::shared_lock oidc_lock(oidc_mu_);
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

        // -- HTTP metrics + CORS (post-routing handler) --------------------------
        web_server_->set_post_routing_handler(
            [this](const httplib::Request& req, httplib::Response& res) {
                // CORS headers for all /api/ responses (H6)
                // Only reflect Origin if it matches the server's own origin
                // to prevent credentialed cross-origin attacks.
                if (req.path.starts_with("/api/")) {
                    auto origin = req.get_header_value("Origin");
                    if (!origin.empty()) {
                        auto scheme = cfg_.https_enabled ? "https" : "http";
                        auto port = cfg_.https_enabled ? cfg_.https_port : cfg_.web_port;
                        auto self_origin =
                            std::format("{}://{}:{}", scheme, cfg_.web_address, port);
                        auto localhost_origin =
                            std::format("{}://localhost:{}", scheme, port);
                        auto loopback_origin =
                            std::format("{}://127.0.0.1:{}", scheme, port);
                        if (origin == self_origin || origin == localhost_origin ||
                            origin == loopback_origin) {
                            res.set_header("Access-Control-Allow-Origin", origin);
                            res.set_header("Access-Control-Allow-Credentials", "true");
                        }
                    }
                    res.set_header("Access-Control-Allow-Methods",
                                   "GET, POST, PUT, DELETE, OPTIONS");
                    res.set_header("Access-Control-Allow-Headers",
                                   "Content-Type, Authorization, X-Yuzu-Token");
                    res.set_header("Access-Control-Max-Age", "86400");
                }

                // Security response headers (G2-SEC-B1-004)
                res.set_header("X-Content-Type-Options", "nosniff");
                res.set_header("X-Frame-Options", "DENY");
                res.set_header("Referrer-Policy", "strict-origin-when-cross-origin");
                if (cfg_.https_enabled)
                    res.set_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

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
        web_server_->Get("/health", [this](const httplib::Request& req, httplib::Response& res) {
            auto now = std::chrono::steady_clock::now();
            auto uptime_sec = std::chrono::duration_cast<std::chrono::seconds>(
                                  now - server_start_time_)
                                  .count();

            // Agent counts
            auto online = registry_.agent_count();
            auto pending_agents = auth_mgr_.list_pending_agents();
            int pending_count = 0;
            for (const auto& a : pending_agents) {
                if (a.status == auth::PendingStatus::pending)
                    ++pending_count;
            }

            // Store health
            auto response_ok = response_store_ && response_store_->is_open();
            auto audit_ok = audit_store_ && audit_store_->is_open();
            auto instruction_ok = instruction_store_ && instruction_store_->is_open();
            auto policy_ok = policy_store_ && policy_store_->is_open();

            // Execution stats
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

            // Determine overall status
            bool all_stores_ok = response_ok && audit_ok && instruction_ok && policy_ok;
            std::string status = all_stores_ok ? "healthy" : "degraded";

            nlohmann::json health = {
                {"status", status},
                {"uptime_seconds", uptime_sec},
                {"agents",
                 {{"online", online}, {"pending", pending_count}}},
                {"stores",
                 {{"responses", response_ok ? "ok" : "error"},
                  {"audit", audit_ok ? "ok" : "error"},
                  {"instructions", instruction_ok ? "ok" : "error"},
                  {"policies", policy_ok ? "ok" : "error"}}},
                {"executions",
                 {{"in_flight", in_flight},
                  {"completed_last_hour", completed_last_hour},
                  {"failed_last_hour", failed_last_hour}}},
                {"version", "0.1.0"}};

            // Process health (22.1) — only include for authenticated requests
            // to avoid leaking process internals to unauthenticated callers.
            // Check auth without returning 401 (health probe must stay open).
            bool is_authenticated = false;
            {
                auto ck = extract_session_cookie(req);
                if (auth_mgr_.validate_session(ck))
                    is_authenticated = true;
                if (!is_authenticated) {
                    auto ah = req.get_header_value("Authorization");
                    if (ah.size() > 7 && ah.substr(0, 7) == "Bearer " && api_token_store_) {
                        if (api_token_store_->validate_token(ah.substr(7)))
                            is_authenticated = true;
                    }
                }
                if (!is_authenticated) {
                    auto xh = req.get_header_value("X-Yuzu-Token");
                    if (!xh.empty() && api_token_store_ && api_token_store_->validate_token(xh))
                        is_authenticated = true;
                }
            }
            if (is_authenticated) {
                auto ph = process_health_sampler_.sample();
                health["system"] = {
                    {"cpu_percent", ph.cpu_percent},
                    {"memory_rss_bytes", static_cast<int64_t>(ph.memory_rss_bytes)},
                    {"memory_vss_bytes", static_cast<int64_t>(ph.memory_vss_bytes)},
                    {"grpc_connections", static_cast<int>(online)},
                    {"command_queue_depth", in_flight}};
            }

            res.set_content(health.dump(), "application/json");
        });

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

            bool stores_ok = (response_store_ && response_store_->is_open()) &&
                             (audit_store_ && audit_store_->is_open()) &&
                             (instruction_store_ && instruction_store_->is_open());

            if (stores_ok) {
                res.set_content(R"({"status":"ready"})", "application/json");
            } else {
                res.status = 503;
                res.set_content(R"({"status":"not ready"})", "application/json");
            }
        });

        // -- Health summary dashboard fragment (7.2) ----------------------------
        web_server_->Get("/fragments/health/summary",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             auto session = require_auth(req, res);
                             if (!session)
                                 return;

                             auto now = std::chrono::steady_clock::now();
                             auto uptime_sec = std::chrono::duration_cast<std::chrono::seconds>(
                                                   now - server_start_time_)
                                                   .count();

                             // Store health
                             bool response_ok = response_store_ && response_store_->is_open();
                             bool audit_ok = audit_store_ && audit_store_->is_open();
                             bool instruction_ok = instruction_store_ && instruction_store_->is_open();
                             bool policy_ok = policy_store_ && policy_store_->is_open();
                             bool all_ok = response_ok && audit_ok && instruction_ok && policy_ok;

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
                                     "<span>Uptime: " + uptime_str + "</span>"
                                     "<span>Agents online: " + std::to_string(online) + "</span>"
                                     "<span>CPU: " + std::string(cpu_buf) + "%</span>"
                                     "<span>Mem: " + std::to_string(rss_mb) + " MB</span>"
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
                                 if (!response_ok) html += "responses ";
                                 if (!audit_ok) html += "audit ";
                                 if (!instruction_ok) html += "instructions ";
                                 if (!policy_ok) html += "policies ";
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
        web_server_->Get("/api/config",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;

                             nlohmann::json config_obj;
                             // Current effective values (from cfg_ + overrides)
                             config_obj["heartbeat_timeout"] = cfg_.session_timeout.count();
                             config_obj["response_retention_days"] = cfg_.response_retention_days;
                             config_obj["audit_retention_days"] = cfg_.audit_retention_days;
                             config_obj["auto_approve_enabled"] = !auto_approve_.list_rules().empty();
                             config_obj["log_level"] = spdlog::level::to_string_view(
                                                           spdlog::default_logger()->level())
                                                           .data();

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
                                 nlohmann::json({{"config", config_obj},
                                                 {"overrides", overrides},
                                                 {"allowed_keys", allowed}})
                                     .dump(),
                                 "application/json");
                         });

        web_server_->Put(R"(/api/config/([a-z_]+))",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Write"))
                                 return;
                             if (!runtime_config_store_ || !runtime_config_store_->is_open()) {
                                 res.status = 503;
                                 res.set_content(R"({"error":{"code":503,"message":"runtime config store unavailable"},"meta":{"api_version":"v1"}})",
                                                 "application/json");
                                 return;
                             }

                             auto key = req.matches[1].str();
                             std::string value;
                             try {
                                 auto j = nlohmann::json::parse(req.body);
                                 if (j.contains("value"))
                                     value = j["value"].is_string() ? j["value"].get<std::string>()
                                                                     : j["value"].dump();
                                 else {
                                     res.status = 400;
                                     res.set_content(R"({"error":{"code":400,"message":"missing 'value' in request body"},"meta":{"api_version":"v1"}})",
                                                     "application/json");
                                     return;
                                 }
                             } catch (...) {
                                 res.status = 400;
                                 res.set_content(R"({"error":{"code":400,"message":"invalid JSON body"},"meta":{"api_version":"v1"}})",
                                                 "application/json");
                                 return;
                             }

                             // Get username from session
                             auto session = require_auth(req, res);
                             if (!session)
                                 return;

                             auto result = runtime_config_store_->set(key, value, session->username);
                             if (!result) {
                                 res.status = 400;
                                 res.set_content(
                                     nlohmann::json({{"error", result.error()}}).dump(),
                                     "application/json");
                                 return;
                             }

                             // Apply the change to in-memory config
                             if (key == "heartbeat_timeout") {
                                 try {
                                     cfg_.session_timeout = std::chrono::seconds(std::stoi(value));
                                 } catch (...) {}
                             } else if (key == "response_retention_days") {
                                 try {
                                     cfg_.response_retention_days = std::stoi(value);
                                 } catch (...) {}
                             } else if (key == "audit_retention_days") {
                                 try {
                                     cfg_.audit_retention_days = std::stoi(value);
                                 } catch (...) {}
                             }
                             // log_level is applied inside RuntimeConfigStore::set()

                             audit_log(req, "config.update", "success", "RuntimeConfig", key,
                                       "value=" + value);

                             res.set_content(
                                 nlohmann::json({{"key", key}, {"value", value}, {"applied", true}})
                                     .dump(),
                                 "application/json");
                         });

        // -- Custom Properties API (7.6) ----------------------------------------

        // GET /api/agents/:id/properties
        web_server_->Get(R"(/api/agents/([^/]+)/properties)",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;
                             if (!custom_properties_store_ || !custom_properties_store_->is_open()) {
                                 res.status = 503;
                                 res.set_content(R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
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
                             res.set_content(
                                 nlohmann::json({{"agent_id", agent_id}, {"properties", arr}}).dump(),
                                 "application/json");
                         });

        // PUT /api/agents/:id/properties/:key
        web_server_->Put(R"(/api/agents/([^/]+)/properties/([a-zA-Z0-9_.:-]+))",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Write"))
                                 return;
                             if (!custom_properties_store_ || !custom_properties_store_->is_open()) {
                                 res.status = 503;
                                 res.set_content(R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
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
                                     value = j["value"].is_string() ? j["value"].get<std::string>()
                                                                     : j["value"].dump();
                                 else {
                                     res.status = 400;
                                     res.set_content(R"({"error":{"code":400,"message":"missing 'value' in request body"},"meta":{"api_version":"v1"}})",
                                                     "application/json");
                                     return;
                                 }
                                 if (j.contains("type") && j["type"].is_string())
                                     type = j["type"].get<std::string>();
                             } catch (...) {
                                 res.status = 400;
                                 res.set_content(R"({"error":{"code":400,"message":"invalid JSON body"},"meta":{"api_version":"v1"}})",
                                                 "application/json");
                                 return;
                             }

                             auto result =
                                 custom_properties_store_->set_property(agent_id, key, value, type);
                             if (!result) {
                                 res.status = 400;
                                 res.set_content(
                                     nlohmann::json({{"error", result.error()}}).dump(),
                                     "application/json");
                                 return;
                             }

                             audit_log(req, "custom_property.set", "success", "Agent", agent_id,
                                       key + "=" + value);

                             res.set_content(
                                 nlohmann::json(
                                     {{"agent_id", agent_id}, {"key", key}, {"value", value}, {"type", type}})
                                     .dump(),
                                 "application/json");
                         });

        // DELETE /api/agents/:id/properties/:key
        web_server_->Delete(R"(/api/agents/([^/]+)/properties/([a-zA-Z0-9_.:-]+))",
                            [this](const httplib::Request& req, httplib::Response& res) {
                                if (!require_permission(req, res, "Infrastructure", "Write"))
                                    return;
                                if (!custom_properties_store_ ||
                                    !custom_properties_store_->is_open()) {
                                    res.status = 503;
                                    res.set_content(
                                        R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
                                        "application/json");
                                    return;
                                }

                                auto agent_id = req.matches[1].str();
                                auto key = req.matches[2].str();

                                bool deleted =
                                    custom_properties_store_->delete_property(agent_id, key);
                                if (!deleted) {
                                    res.status = 404;
                                    res.set_content(R"({"error":{"code":404,"message":"property not found"},"meta":{"api_version":"v1"}})",
                                                    "application/json");
                                    return;
                                }

                                audit_log(req, "custom_property.delete", "success", "Agent",
                                          agent_id, "key=" + key);

                                res.set_content(
                                    nlohmann::json({{"deleted", true}, {"key", key}}).dump(),
                                    "application/json");
                            });

        // GET /api/property-schemas
        web_server_->Get("/api/property-schemas",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;
                             if (!custom_properties_store_ || !custom_properties_store_->is_open()) {
                                 res.status = 503;
                                 res.set_content(R"({"error":{"code":503,"message":"custom properties store unavailable"},"meta":{"api_version":"v1"}})",
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
                             res.set_content(nlohmann::json({{"schemas", arr}}).dump(),
                                             "application/json");
                         });

        // POST /api/property-schemas
        web_server_->Post("/api/property-schemas",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_permission(req, res, "Infrastructure", "Write"))
                                  return;
                              if (!custom_properties_store_ ||
                                  !custom_properties_store_->is_open()) {
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
                                  res.set_content(R"({"error":{"code":400,"message":"invalid JSON body"},"meta":{"api_version":"v1"}})",
                                                  "application/json");
                                  return;
                              }

                              if (schema.key.empty()) {
                                  res.status = 400;
                                  res.set_content(R"({"error":{"code":400,"message":"'key' is required"},"meta":{"api_version":"v1"}})",
                                                  "application/json");
                                  return;
                              }

                              auto result = custom_properties_store_->upsert_schema(schema);
                              if (!result) {
                                  res.status = 400;
                                  res.set_content(
                                      nlohmann::json({{"error", result.error()}}).dump(),
                                      "application/json");
                                  return;
                              }

                              audit_log(req, "property_schema.create", "success",
                                        "PropertySchema", schema.key);

                              res.status = 201;
                              res.set_content(
                                  nlohmann::json({{"key", schema.key},
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

            if (req.has_param("type")) {
                type = req.get_param_value("type");
            }

            if (YUZU_REQ_HAS_FILE(req, "file")) {
                content = YUZU_REQ_GET_FILE(req, "file").content;
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

            // Set restrictive permissions for private key files
#ifndef _WIN32
            if (type == "key") {
                std::filesystem::permissions(out_path,
                    std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                    std::filesystem::perm_options::replace);
            }
#endif

            spdlog::info("Certificate uploaded: {} → {}", type, out_path.string());
            audit_log(req, "cert.upload", "success", "Certificate", type, "");

            // Re-render TLS section to show new file paths
            res.set_header("HX-Retarget", "#tls-section");
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Certificate uploaded","level":"success"}})");
            res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
        });

        // -- Settings API: Paste PEM content (admin only, HTMX) ----------------
        web_server_->Post("/api/settings/cert-paste", [this](const httplib::Request& req,
                                                              httplib::Response& res) {
            if (!require_admin(req, res))
                return;

            auto type = extract_form_value(req.body, "type");
            auto content = extract_form_value(req.body, "content");

            if (type.empty() || content.empty()) {
                res.status = 400;
                res.set_header("HX-Retarget", "#tls-section");
                res.set_content("<span class=\"feedback-error\">Type and PEM content are required.</span>",
                                "text/html; charset=utf-8");
                return;
            }

            // Size limit (64 KB — typical cert chains are under 10 KB)
            if (content.size() > 65536) {
                res.status = 400;
                res.set_header("HX-Retarget", "#tls-section");
                res.set_content(
                    "<span class=\"feedback-error\">PEM content too large (max 64 KB).</span>",
                    "text/html; charset=utf-8");
                return;
            }

            // PEM validation: must contain -----BEGIN and matching -----END
            if (content.find("-----BEGIN") == std::string::npos ||
                content.find("-----END") == std::string::npos) {
                res.status = 400;
                res.set_header("HX-Retarget", "#tls-section");
                res.set_content(
                    "<span class=\"feedback-error\">Invalid PEM: must contain -----BEGIN and -----END markers.</span>",
                    "text/html; charset=utf-8");
                return;
            }

            // Normalize line endings: strip \r so we always write \n
            std::erase(content, '\r');

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
                res.set_header("HX-Retarget", "#tls-section");
                res.set_content(
                    "<span class=\"feedback-error\">Type must be cert, key, or ca.</span>",
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

            // Set restrictive permissions for private key files
#ifndef _WIN32
            if (type == "key") {
                std::filesystem::permissions(out_path,
                    std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                    std::filesystem::perm_options::replace);
            }
#endif

            // Update config
            if (type == "cert")
                cfg_.tls_server_cert = out_path;
            else if (type == "key")
                cfg_.tls_server_key = out_path;
            else if (type == "ca")
                cfg_.tls_ca_cert = out_path;

            spdlog::info("Certificate pasted: {} → {}", type, out_path.string());
            audit_log(req, "cert.paste", "success", "Certificate", type, "");

            // Re-render TLS section to show new file paths
            res.set_header("HX-Retarget", "#tls-section");
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Certificate saved from paste","level":"success"}})");
            res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
        });

        // -- Settings API: OIDC configuration (admin only, HTMX) ---------------
        web_server_->Post(
            "/api/settings/oidc", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res))
                    return;

                auto issuer = extract_form_value(req.body, "issuer");
                auto client_id = extract_form_value(req.body, "client_id");
                auto client_secret = extract_form_value(req.body, "client_secret");
                auto redirect_uri = extract_form_value(req.body, "redirect_uri");
                auto admin_group = extract_form_value(req.body, "admin_group");
                auto skip_tls_verify = extract_form_value(req.body, "skip_tls_verify");

                // Validate required fields
                if (issuer.empty() || client_id.empty()) {
                    res.status = 400;
                    auto html = render_directory_fragment() +
                        "<div id=\"oidc-feedback\" class=\"feedback feedback-error\" "
                        "hx-swap-oob=\"true\">Issuer URL and Client ID are required.</div>";
                    res.set_content(html, "text/html; charset=utf-8");
                    return;
                }

                // Resolve effective client secret (keep existing if not provided)
                auto effective_secret = client_secret.empty() ? cfg_.oidc_client_secret : client_secret;
                bool skip_tls = (skip_tls_verify == "true");

                // Build OIDC config and try to initialize BEFORE mutating cfg_
                std::unique_ptr<oidc::OidcProvider> new_provider;
                try {
                    oidc::OidcConfig oidc_cfg;
                    oidc_cfg.issuer = issuer;
                    oidc_cfg.client_id = client_id;
                    oidc_cfg.client_secret = effective_secret;
                    oidc_cfg.redirect_uri = redirect_uri;
                    oidc_cfg.admin_group_id = admin_group;
                    oidc_cfg.skip_tls_verify = skip_tls;
                    if (skip_tls)
                        spdlog::warn("OIDC TLS certificate verification DISABLED — do not use in production");

                    // Compute endpoints from issuer (Entra v2.0 pattern)
                    auto v2_pos = issuer.rfind("/v2.0");
                    if (v2_pos != std::string::npos) {
                        auto base = issuer.substr(0, v2_pos);
                        oidc_cfg.authorization_endpoint = base + "/oauth2/v2.0/authorize";
                        oidc_cfg.token_endpoint = base + "/oauth2/v2.0/token";
                    } else {
                        oidc_cfg.authorization_endpoint = issuer + "/authorize";
                        oidc_cfg.token_endpoint = issuer + "/token";
                    }

                    // Locate token exchange helper script
                    auto src_script =
                        std::filesystem::current_path() / "scripts" / "oidc_token_exchange.py";
                    if (std::filesystem::exists(src_script))
                        oidc_cfg.exchange_script = src_script.string();

                    new_provider = std::make_unique<oidc::OidcProvider>(std::move(oidc_cfg));
                } catch (const std::exception& e) {
                    spdlog::error("OIDC provider reinit failed: {}", e.what());
                    res.status = 500;
                    auto html = render_directory_fragment() +
                        "<div id=\"oidc-feedback\" class=\"feedback feedback-error\" "
                        "hx-swap-oob=\"true\">OIDC init failed: " + html_escape(e.what()) + "</div>";
                    res.set_content(html, "text/html; charset=utf-8");
                    return;
                }

                // Success — now atomically update cfg_ and provider under exclusive lock
                {
                    std::unique_lock lock(oidc_mu_);
                    cfg_.oidc_issuer = issuer;
                    cfg_.oidc_client_id = client_id;
                    cfg_.oidc_client_secret = effective_secret;
                    cfg_.oidc_redirect_uri = redirect_uri;
                    cfg_.oidc_admin_group = admin_group;
                    cfg_.oidc_skip_tls_verify = skip_tls;
                    oidc_provider_ = std::move(new_provider);
                }
                spdlog::info("OIDC provider reinitialized via Settings UI (issuer={})", issuer);

                // Persist to RuntimeConfigStore so config survives restart
                if (runtime_config_store_ && runtime_config_store_->is_open()) {
                    auto who = "admin"; // Settings UI requires admin
                    auto session = require_auth(req, res);
                    if (session) who = session->username.c_str();
                    runtime_config_store_->set("oidc_issuer", issuer, who);
                    runtime_config_store_->set("oidc_client_id", client_id, who);
                    if (!client_secret.empty())
                        runtime_config_store_->set("oidc_client_secret", client_secret, who);
                    runtime_config_store_->set("oidc_redirect_uri", redirect_uri, who);
                    runtime_config_store_->set("oidc_admin_group", admin_group, who);
                    runtime_config_store_->set("oidc_skip_tls_verify", skip_tls ? "true" : "false", who);
                }

                audit_log(req, "oidc.configure", "success", "OidcConfig", issuer, "");

                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"OIDC configuration saved","level":"success"}})");
                res.set_content(render_directory_fragment(), "text/html; charset=utf-8");
            });

        // -- Settings API: OIDC test connection (admin only, HTMX) --------------
        web_server_->Post(
            "/api/settings/oidc/test", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res))
                    return;

                auto issuer = extract_form_value(req.body, "issuer");
                auto skip_tls_str = extract_form_value(req.body, "skip_tls_verify");
                bool skip_tls = (skip_tls_str == "true") || cfg_.oidc_skip_tls_verify;

                // Use form value if provided, otherwise use current cfg
                if (issuer.empty())
                    issuer = cfg_.oidc_issuer;

                if (issuer.empty()) {
                    res.set_content(
                        "<span class=\"feedback-error\">Enter an Issuer URL first.</span>",
                        "text/html; charset=utf-8");
                    return;
                }

                auto discovery_url = issuer;
                if (!discovery_url.ends_with("/"))
                    discovery_url += "/";
                discovery_url += ".well-known/openid-configuration";

                audit_log(req, "oidc.test", "attempt", "OidcConfig", issuer, "");

                try {
                    // Parse URL for httplib
                    std::string url = discovery_url;
                    std::string scheme;
                    if (url.starts_with("https://")) {
                        scheme = "https://";
                        url = url.substr(8);
                    } else if (url.starts_with("http://")) {
                        scheme = "http://";
                        url = url.substr(7);
                    } else {
                        res.set_content(
                            "<span class=\"feedback-error\">Invalid issuer URL scheme (must be http or https).</span>",
                            "text/html; charset=utf-8");
                        return;
                    }
                    auto slash = url.find('/');
                    auto host = (slash != std::string::npos) ? url.substr(0, slash) : url;
                    auto path = (slash != std::string::npos) ? url.substr(slash) : "/";

                    // Heap-allocated client to avoid httplib SSLClient destructor issues
                    auto client = std::make_unique<httplib::Client>(scheme + host);
                    client->set_connection_timeout(10);
                    client->set_read_timeout(10);
                    client->enable_server_certificate_verification(!skip_tls);

                    auto result = client->Get(path);

                    // Copy result before destroying the client
                    int status_code = result ? result->status : 0;
                    std::string body_copy = result ? result->body : "";
                    std::string err_str = result ? "" : httplib::to_string(result.error());
                    client.reset(); // Explicit destroy before any return

                    if (status_code == 200) {
                        // Verify it looks like a valid discovery document
                        auto j = nlohmann::json::parse(body_copy);
                        std::string auth_ep = j.value("authorization_endpoint", "");
                        std::string token_ep = j.value("token_endpoint", "");
                        if (!auth_ep.empty() && !token_ep.empty()) {
                            res.set_content(
                                "<span class=\"feedback-ok\" style=\"color:#3fb950;font-size:0.8rem\">"
                                "Connected &#x2014; discovered authorization and token endpoints</span>",
                                "text/html; charset=utf-8");
                        } else {
                            res.set_content(
                                "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                                "Discovery succeeded but missing authorization/token endpoints.</span>",
                                "text/html; charset=utf-8");
                        }
                    } else if (status_code == 0) {
                        res.set_content(
                            "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                            "Discovery failed: " + html_escape(err_str) + "</span>",
                            "text/html; charset=utf-8");
                    } else {
                        res.set_content(
                            "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                            "Discovery failed: HTTP " + std::to_string(status_code) + "</span>",
                            "text/html; charset=utf-8");
                    }
                } catch (const nlohmann::json::exception& e) {
                    res.set_content(
                        "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                        "Discovery response is not valid JSON: " + html_escape(e.what()) + "</span>",
                        "text/html; charset=utf-8");
                } catch (const std::exception& e) {
                    res.set_content(
                        "<span class=\"feedback-error\" style=\"color:#f85149;font-size:0.8rem\">"
                        "Discovery failed: " + html_escape(e.what()) + "</span>",
                        "text/html; charset=utf-8");
                }
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
                res.set_content(R"({"error":{"code":400,"message":"invalid numeric parameter"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":400,"message":"invalid numeric parameter"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            if (count < 1 || count > 10000) {
                res.status = 400;
                res.set_content(R"({"error":{"code":400,"message":"count must be 1-10000"},"meta":{"api_version":"v1"}})", "application/json");
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
            auto mcp_tier = extract_form_value(req.body, "mcp_tier");

            if (name.empty()) {
                res.set_content(
                    "<span class=\"feedback-error\">Token name is required.</span>",
                    "text/html; charset=utf-8");
                return;
            }

            // Validate MCP tier value
            if (!mcp_tier.empty() && mcp_tier != "readonly" && mcp_tier != "operator" && mcp_tier != "supervised") {
                res.set_content(
                    "<span class=\"feedback-error\">Invalid MCP tier. Must be readonly, operator, or supervised.</span>",
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

            auto result = api_token_store_->create_token(name, session->username, expires_at, {}, mcp_tier);
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

        web_server_->Get("/fragments/settings/gateway",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_admin(req, res))
                                 return;
                             res.set_content(render_gateway_fragment(), "text/html; charset=utf-8");
                         });

        web_server_->Get("/fragments/settings/server-config",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_admin(req, res))
                                 return;
                             res.set_content(render_server_config_fragment(),
                                             "text/html; charset=utf-8");
                         });

        web_server_->Get("/fragments/settings/https",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_admin(req, res))
                                 return;
                             res.set_content(render_https_fragment(), "text/html; charset=utf-8");
                         });

        web_server_->Get("/fragments/settings/analytics",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_admin(req, res))
                                 return;
                             res.set_content(render_analytics_fragment(),
                                             "text/html; charset=utf-8");
                         });

        web_server_->Get("/fragments/settings/data-retention",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_admin(req, res))
                                 return;
                             res.set_content(render_data_retention_fragment(),
                                             "text/html; charset=utf-8");
                         });

        web_server_->Get("/fragments/settings/mcp",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_admin(req, res))
                                 return;
                             res.set_content(render_mcp_fragment(),
                                             "text/html; charset=utf-8");
                         });

        web_server_->Post("/api/settings/mcp",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_admin(req, res))
                                  return;
                              auto enabled_val = extract_form_value(req.body, "enabled");
                              auto read_only_val = extract_form_value(req.body, "read_only");
                              cfg_.mcp_disable = (enabled_val != "true");
                              cfg_.mcp_read_only = (read_only_val == "true");
                              spdlog::info("MCP settings changed: enabled={}, read_only={}",
                                           !cfg_.mcp_disable, cfg_.mcp_read_only);
                              audit_log(req, "settings.mcp", "success", "MCP",
                                        "mcp_settings",
                                        "enabled=" + std::string(!cfg_.mcp_disable ? "true" : "false") +
                                        ", read_only=" + std::string(cfg_.mcp_read_only ? "true" : "false"));
                              res.set_header("HX-Trigger",
                                  R"({"showToast":{"message":"MCP settings saved","level":"success"}})");
                              res.set_content(render_mcp_fragment(),
                                              "text/html; charset=utf-8");
                          });

        web_server_->Get("/fragments/settings/nvd",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_admin(req, res))
                                 return;
                             res.set_content(render_nvd_fragment(), "text/html; charset=utf-8");
                         });

        web_server_->Get("/fragments/settings/directory",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_admin(req, res))
                                 return;
                             res.set_content(render_directory_fragment(),
                                             "text/html; charset=utf-8");
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
            if (req.has_param("platform"))
                platform = req.get_param_value("platform");
            if (req.has_param("arch"))
                arch = req.get_param_value("arch");
            if (req.has_param("rollout_pct"))
                rollout_s = req.get_param_value("rollout_pct");
            if (req.has_param("mandatory"))
                mandatory_s = req.get_param_value("mandatory");

            if (!YUZU_REQ_HAS_FILE(req, "file")) {
                res.status = 400;
                res.set_content("<span class=\"feedback-error\">No file uploaded.</span>",
                                "text/html; charset=utf-8");
                return;
            }
            auto uploaded = YUZU_REQ_GET_FILE(req, "file");
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

        web_server_->Get("/api/agents", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;
            auto session = require_auth(req, res);
            if (!session) return;
            res.set_content(get_visible_agents_json(session->username).dump(),
                            "application/json");
        });

        // -- Scope panel fragment (HTMX polling) --------------------------------

        web_server_->Get("/fragments/scope-list", [this](const httplib::Request& req,
                                                         httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;
            auto session = require_auth(req, res);
            if (!session) return;

            std::string selected = req.get_param_value("selected");
            if (selected.empty()) selected = "__all__";

            auto agents_arr = get_visible_agents_json(session->username);

            // Sort by agent_id
            std::sort(agents_arr.begin(), agents_arr.end(),
                      [](const nlohmann::json& a, const nlohmann::json& b) {
                          return a.value("agent_id", "") < b.value("agent_id", "");
                      });

            std::string html;
            html.reserve(agents_arr.size() * 400 + 2048);

            // "All Agents" item
            html += "<div class=\"scope-item";
            if (selected == "__all__") html += " selected";
            html += "\" data-agent-id=\"__all__\" onclick=\"selectScope(this)\">"
                    "<span class=\"scope-item-name scope-item-all\">All Agents</span>"
                    "<span class=\"scope-item-meta\">Broadcast to every connected agent</span>"
                    "</div>";

            // Individual agents
            for (const auto& a : agents_arr) {
                auto id = a.value("agent_id", "");
                auto hostname = a.value("hostname", "");
                auto os = a.value("os", "?");
                auto arch = a.value("arch", "?");
                auto version = a.value("agent_version", "");
                auto short_id = (id.size() > 12) ? id.substr(0, 12) : id;

                html += "<div class=\"scope-item";
                if (selected == id) html += " selected";
                html += "\" data-agent-id=\"" + html_escape(id) +
                        "\" onclick=\"selectScope(this)\">"
                        "<span class=\"scope-item-name\"><span class=\"online-dot\"></span>" +
                        html_escape(hostname.empty() ? id : hostname) +
                        "</span><span class=\"scope-item-meta\">" +
                        html_escape(short_id) + " &middot; " +
                        html_escape(os) + "/" + html_escape(arch) +
                        (version.empty() ? "" : " &middot; v" + html_escape(version)) +
                        "</span></div>";
            }

            // OOB: agent count badge
            auto count = agents_arr.size();
            html += "<span id=\"agent-count\" hx-swap-oob=\"true\">" +
                    std::to_string(count) + " agent" +
                    (count != 1u ? "s" : "") + "</span>";

            // Hidden data carrier — bridges agent JSON to client-side JS state
            html += "<div id=\"scope-data\" data-agents=\"" +
                    html_escape(agents_arr.dump()) +
                    "\" style=\"display:none\"></div>";

            res.set_content(html, "text/html");
        });

        web_server_->Get("/api/help", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;
            res.set_content(registry_.help_json(), "application/json");
        });

        // Help table HTML fragment (HTMX)
        web_server_->Get("/api/help/html", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;
            std::string filter;
            if (req.has_param("filter")) filter = req.get_param_value("filter");
            res.set_content(registry_.help_html(filter), "text/html");
        });

        // Autocomplete HTML fragment (HTMX)
        web_server_->Get("/api/help/autocomplete", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;
            std::string q;
            if (req.has_param("q")) q = req.get_param_value("q");
            if (q.empty()) { res.set_content("", "text/html"); return; }
            res.set_content(registry_.autocomplete_html(q), "text/html");
        });

        // Command palette instruction search HTML fragment (HTMX)
        web_server_->Get("/api/help/palette", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_permission(req, res, "Infrastructure", "Read"))
                return;
            std::string q;
            if (req.has_param("q")) q = req.get_param_value("q");
            if (q.empty()) { res.set_content("", "text/html"); return; }
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

        web_server_->Post(
            "/api/nvd/sync", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Infrastructure", "Execute"))
                    return;
                if (!nvd_sync_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"NVD sync not enabled"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"NVD database not available"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":400,"message":"invalid JSON body"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":400,"message":"plugin and action are required"},"meta":{"api_version":"v1"}})",
                                "application/json");
                return;
            }

            // All commands require Execution:Execute permission
            if (!require_permission(req, res, "Execution", "Execute"))
                return;

            if (!registry_.has_any()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"no agent connected"},"meta":{"api_version":"v1"}})", "application/json");
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
                auto matched_ids = registry_.evaluate_scope(*parsed, tag_store_.get(), custom_properties_store_.get());
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
                res.set_content(R"({"error":{"code":503,"message":"failed to send command to any agent"},"meta":{"api_version":"v1"}})",
                                "application/json");
                return;
            }

            metrics_.counter("yuzu_commands_dispatched_total").increment();
            event_bus_.publish("command-status",
                "<span id=\"status-badge\" class=\"badge-running\""
                " hx-swap-oob=\"outerHTML\">RUNNING</span>");
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
                    {{"status", "sent"},
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
                res.set_content(R"({"error":{"code":503,"message":"response store not available"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"response store not available"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":400,"message":"instruction_id required"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            if (!response_store_ || !response_store_->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"response store not available"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"audit store not available"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"tag store not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto agent_id = req.get_param_value("agent_id");
            if (agent_id.empty()) {
                res.status = 400;
                res.set_content(R"({"error":{"code":400,"message":"agent_id parameter required"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":503,"message":"tag store not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto agent_id = extract_json_string(req.body, "agent_id");
                auto key = extract_json_string(req.body, "key");
                auto value = extract_json_string(req.body, "value");

                if (agent_id.empty() || key.empty()) {
                    res.status = 400;
                    res.set_content(R"({"error":{"code":400,"message":"agent_id and key required"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                if (!TagStore::validate_key(key)) {
                    res.status = 400;
                    res.set_content(R"({"error":{"code":400,"message":"invalid tag key"},"meta":{"api_version":"v1"}})", "application/json");
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

        web_server_->Post(
            "/api/tags/delete", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Tag", "Delete"))
                    return;
                if (!tag_store_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"tag store not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto agent_id = extract_json_string(req.body, "agent_id");
                auto key = extract_json_string(req.body, "key");

                if (agent_id.empty() || key.empty()) {
                    res.status = 400;
                    res.set_content(R"({"error":{"code":400,"message":"agent_id and key required"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":503,"message":"tag store not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto key = extract_json_string(req.body, "key");
                auto value = extract_json_string(req.body, "value");

                if (key.empty()) {
                    res.status = 400;
                    res.set_content(R"({"error":{"code":400,"message":"key required"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":400,"message":"invalid JSON array"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"instruction store not available"},"meta":{"api_version":"v1"}})",
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
                res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto def = instruction_store_->get_definition(id);
            if (!def) {
                res.status = 404;
                res.set_content(R"({"error":{"code":404,"message":"not found"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                                 res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto exec = execution_tracker_->get_execution(id);
            if (!exec) {
                res.status = 404;
                res.set_content(R"({"error":{"code":404,"message":"not found"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                                  res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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

                // Validate scope expression before storing (G2-SEC-D2-005)
                if (!sched.scope_expression.empty()) {
                    auto scope_check = yuzu::scope::validate(sched.scope_expression);
                    if (!scope_check) {
                        res.status = 400;
                        res.set_content(
                            nlohmann::json({{"error", "invalid scope_expression: " + scope_check.error()}}).dump(),
                            "application/json");
                        return;
                    }
                }

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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto enabled_str = extract_json_string(req.body, "enabled");
            bool enabled = (enabled_str != "false");
            schedule_engine_->set_enabled(id, enabled);
            audit_log(req, enabled ? "schedule.enable" : "schedule.disable",
                      "success", "schedule", id);
            res.set_content(nlohmann::json({{"enabled", enabled}}).dump(), "application/json");
        });

        // -- Approval API -----------------------------------------------------

        web_server_->Get(
            "/api/approvals", [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Approval", "Read"))
                    return;
                if (!approval_manager_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":400,"message":"expression required"},"meta":{"api_version":"v1"}})", "application/json");
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
                res.set_content(R"({"error":{"code":400,"message":"expression required"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto parsed = yuzu::scope::parse(expression);
            if (!parsed) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", parsed.error()}}).dump(),
                                "application/json");
                return;
            }

            auto matched = registry_.evaluate_scope(*parsed, tag_store_.get(), custom_properties_store_.get());
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
                    res.set_content(R"({"error":{"code":503,"message":"policy store not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                FragmentQuery q;
                if (req.has_param("name"))
                    q.name_filter = req.get_param_value("name");
                try {
                    if (req.has_param("limit"))
                        q.limit = std::stoi(req.get_param_value("limit"));
                } catch (const std::exception&) {
                    res.status = 400;
                    res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

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
                    res.set_content(R"({"error":{"code":503,"message":"policy store not available"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":503,"message":"policy store not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                PolicyQuery q;
                if (req.has_param("name"))
                    q.name_filter = req.get_param_value("name");
                if (req.has_param("fragment_id"))
                    q.fragment_filter = req.get_param_value("fragment_id");
                if (req.has_param("enabled_only"))
                    q.enabled_only = true;
                try {
                    if (req.has_param("limit"))
                        q.limit = std::stoi(req.get_param_value("limit"));
                } catch (const std::exception&) {
                    res.status = 400;
                    res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

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
                    res.set_content(R"({"error":{"code":503,"message":"policy store not available"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto id = req.matches[1].str();
                auto policy = policy_store_->get_policy(id);
                if (!policy) {
                    res.status = 404;
                    res.set_content(R"({"error":{"code":404,"message":"policy not found"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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

        // POST /api/policies/:id/invalidate — invalidate cache for one policy
        web_server_->Post(R"(/api/policies/([^/]+)/invalidate)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Execute"))
                    return;
                if (!policy_store_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto id = req.matches[1].str();
                auto result = policy_store_->invalidate_policy(id);
                if (!result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                    return;
                }
                audit_log(req, "policy.invalidate", "success", "policy", id);
                emit_event("policy.invalidated", req, {}, {{"policy_id", id}, {"agents_reset", std::to_string(*result)}});
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"Policy cache invalidated","level":"success"}})");
                res.set_content(
                    nlohmann::json({{"status", "ok"}, {"agents_invalidated", *result}}).dump(),
                    "application/json");
            });

        // POST /api/policies/invalidate-all — invalidate cache for all policies
        web_server_->Post("/api/policies/invalidate-all",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Execute"))
                    return;
                if (!policy_store_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto result = policy_store_->invalidate_all_policies();
                if (!result) {
                    res.status = 500;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                    return;
                }
                audit_log(req, "policy.invalidate_all", "success");
                emit_event("policy.invalidated_all", req, {}, {{"total_reset", std::to_string(*result)}});
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"All policy caches invalidated","level":"success"}})");
                res.set_content(
                    nlohmann::json({{"status", "ok"}, {"total_invalidated", *result}}).dump(),
                    "application/json");
            });

        // GET /api/compliance — fleet compliance summary
        web_server_->Get("/api/compliance",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Policy", "Read"))
                    return;
                if (!policy_store_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
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

        // -- Workflow Engine API (Phase 7) -------------------------------------------

        // GET /api/workflows — list all workflows
        web_server_->Get("/api/workflows",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Workflow", "Read"))
                    return;
                if (!workflow_engine_ || !workflow_engine_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"workflow engine not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                WorkflowQuery q;
                if (req.has_param("name"))
                    q.name_filter = req.get_param_value("name");
                try {
                    if (req.has_param("limit"))
                        q.limit = std::stoi(req.get_param_value("limit"));
                } catch (const std::exception&) {
                    res.status = 400;
                    res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto workflows = workflow_engine_->list_workflows(q);
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& w : workflows) {
                    nlohmann::json steps_arr = nlohmann::json::array();
                    for (const auto& s : w.steps) {
                        steps_arr.push_back({{"index", s.index},
                                             {"instruction_id", s.instruction_id},
                                             {"label", s.label},
                                             {"condition", s.condition},
                                             {"retry_count", s.retry_count},
                                             {"foreach", s.foreach_source},
                                             {"on_failure", s.on_failure}});
                    }
                    arr.push_back({{"id", w.id},
                                   {"name", w.name},
                                   {"description", w.description},
                                   {"steps", steps_arr},
                                   {"step_count", w.steps.size()},
                                   {"created_at", w.created_at},
                                   {"updated_at", w.updated_at}});
                }
                res.set_content(
                    nlohmann::json({{"workflows", arr}, {"count", arr.size()}}).dump(),
                    "application/json");
            });

        // POST /api/workflows — create workflow from YAML
        web_server_->Post("/api/workflows",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Workflow", "Write"))
                    return;
                if (!workflow_engine_ || !workflow_engine_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"workflow engine not available"},"meta":{"api_version":"v1"}})", "application/json");
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

                auto result = workflow_engine_->create_workflow(yaml_source);
                if (!result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                    return;
                }
                audit_log(req, "workflow.create", "success", "workflow", *result);
                emit_event("workflow.created", req, {}, {{"workflow_id", *result}});
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"Workflow created","level":"success"}})");
                res.status = 201;
                res.set_content(nlohmann::json({{"id", *result}, {"status", "created"}}).dump(),
                                "application/json");
            });

        // GET /api/workflows/:id — get workflow detail
        web_server_->Get(R"(/api/workflows/([^/]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Workflow", "Read"))
                    return;
                if (!workflow_engine_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto id = req.matches[1].str();
                auto workflow = workflow_engine_->get_workflow(id);
                if (!workflow) {
                    res.status = 404;
                    res.set_content(R"({"error":{"code":404,"message":"workflow not found"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                nlohmann::json steps_arr = nlohmann::json::array();
                for (const auto& s : workflow->steps) {
                    steps_arr.push_back({{"index", s.index},
                                         {"instruction_id", s.instruction_id},
                                         {"label", s.label},
                                         {"condition", s.condition},
                                         {"retry_count", s.retry_count},
                                         {"retry_delay_seconds", s.retry_delay_seconds},
                                         {"foreach", s.foreach_source},
                                         {"on_failure", s.on_failure}});
                }

                res.set_content(
                    nlohmann::json({{"id", workflow->id},
                                    {"name", workflow->name},
                                    {"description", workflow->description},
                                    {"yaml_source", workflow->yaml_source},
                                    {"steps", steps_arr},
                                    {"created_at", workflow->created_at},
                                    {"updated_at", workflow->updated_at}})
                        .dump(),
                    "application/json");
            });

        // DELETE /api/workflows/:id — delete workflow
        web_server_->Delete(R"(/api/workflows/([^/]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Workflow", "Delete"))
                    return;
                if (!workflow_engine_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto id = req.matches[1].str();
                bool deleted = workflow_engine_->delete_workflow(id);
                if (deleted) {
                    audit_log(req, "workflow.delete", "success", "workflow", id);
                    emit_event("workflow.deleted", req, {}, {{"workflow_id", id}});
                    res.set_header("HX-Trigger",
                        R"({"showToast":{"message":"Workflow deleted","level":"success"}})");
                }
                res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
            });

        // POST /api/workflows/:id/execute — execute workflow against agents
        web_server_->Post(R"(/api/workflows/([^/]+)/execute)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Workflow", "Execute"))
                    return;
                if (!workflow_engine_ || !workflow_engine_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"workflow engine not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto workflow_id = req.matches[1].str();

                // Parse agent_ids from request body
                std::vector<std::string> agent_ids;
                try {
                    auto j = nlohmann::json::parse(req.body);
                    if (j.contains("agent_ids") && j["agent_ids"].is_array()) {
                        for (const auto& aid : j["agent_ids"])
                            agent_ids.push_back(aid.get<std::string>());
                    }
                } catch (const std::exception& e) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                    return;
                }

                if (agent_ids.empty()) {
                    res.status = 400;
                    res.set_content(R"({"error":{"code":400,"message":"agent_ids array is required"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                // Create a dispatch function that uses the existing command dispatch
                auto dispatch_fn = [](const std::string& instruction_id,
                                      const std::string& agent_ids_json,
                                      const std::string& parameters_json)
                    -> std::expected<std::string, std::string> {
                    // In a production system this would dispatch via the gRPC
                    // CommandRequest mechanism. For now, return a placeholder
                    // result that the execution can track.
                    return nlohmann::json({{"status", "dispatched"},
                                           {"instruction_id", instruction_id},
                                           {"agents", nlohmann::json::parse(agent_ids_json, nullptr, false)},
                                           {"parameters", nlohmann::json::parse(parameters_json, nullptr, false)}})
                        .dump();
                };

                // Condition evaluator using compliance_eval
                auto condition_fn = [](const std::string& expression,
                                       const std::map<std::string, std::string>& fields) -> bool {
                    return evaluate_compliance_bool(expression, fields);
                };

                auto result = workflow_engine_->execute(
                    workflow_id, agent_ids, dispatch_fn, condition_fn);

                if (!result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                    return;
                }
                audit_log(req, "workflow.execute", "success", "workflow", workflow_id,
                          "execution_id=" + *result);
                emit_event("workflow.executed", req, {},
                           {{"workflow_id", workflow_id}, {"execution_id", *result}});
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"Workflow execution started","level":"success"}})");
                res.status = 202;
                res.set_content(
                    nlohmann::json({{"execution_id", *result}, {"status", "running"}}).dump(),
                    "application/json");
            });

        // GET /api/workflow-executions/:id — get execution status
        web_server_->Get(R"(/api/workflow-executions/([^/]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Workflow", "Read"))
                    return;
                if (!workflow_engine_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto id = req.matches[1].str();
                auto exec = workflow_engine_->get_execution(id);
                if (!exec) {
                    res.status = 404;
                    res.set_content(R"({"error":{"code":404,"message":"execution not found"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                nlohmann::json steps_arr = nlohmann::json::array();
                for (const auto& sr : exec->step_results) {
                    steps_arr.push_back({{"step_index", sr.step_index},
                                         {"instruction_id", sr.instruction_id},
                                         {"status", sr.status},
                                         {"result", nlohmann::json::parse(sr.result_json, nullptr, false)},
                                         {"started_at", sr.started_at},
                                         {"completed_at", sr.completed_at},
                                         {"attempt", sr.attempt}});
                }

                res.set_content(
                    nlohmann::json({{"id", exec->id},
                                    {"workflow_id", exec->workflow_id},
                                    {"status", exec->status},
                                    {"agent_ids", nlohmann::json::parse(exec->agent_ids_json, nullptr, false)},
                                    {"current_step", exec->current_step},
                                    {"started_at", exec->started_at},
                                    {"completed_at", exec->completed_at},
                                    {"steps", steps_arr}})
                        .dump(),
                    "application/json");
            });

        // -- Product Pack API (Phase 7) -------------------------------------------

        // GET /api/product-packs — list installed product packs
        web_server_->Get("/api/product-packs",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "ProductPack", "Read"))
                    return;
                if (!product_pack_store_ || !product_pack_store_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"product pack store not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                ProductPackQuery q;
                if (req.has_param("name"))
                    q.name_filter = req.get_param_value("name");
                try {
                    if (req.has_param("limit"))
                        q.limit = std::stoi(req.get_param_value("limit"));
                } catch (const std::exception&) {
                    res.status = 400;
                    res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto packs = product_pack_store_->list(q);
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& p : packs) {
                    nlohmann::json items_arr = nlohmann::json::array();
                    for (const auto& item : p.items) {
                        items_arr.push_back({{"kind", item.kind},
                                             {"item_id", item.item_id},
                                             {"name", item.name}});
                    }
                    arr.push_back({{"id", p.id},
                                   {"name", p.name},
                                   {"version", p.version},
                                   {"description", p.description},
                                   {"item_count", p.items.size()},
                                   {"items", items_arr},
                                   {"installed_at", p.installed_at},
                                   {"verified", p.verified}});
                }
                res.set_content(
                    nlohmann::json({{"product_packs", arr}, {"count", arr.size()}}).dump(),
                    "application/json");
            });

        // POST /api/product-packs — install product pack from YAML bundle
        web_server_->Post("/api/product-packs",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "ProductPack", "Write"))
                    return;
                if (!product_pack_store_ || !product_pack_store_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"product pack store not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                std::string yaml_bundle;
                if (req.get_header_value("Content-Type").find("application/json") != std::string::npos) {
                    try {
                        auto j = nlohmann::json::parse(req.body);
                        yaml_bundle = j.value("yaml_source", "");
                    } catch (const std::exception& e) {
                        res.status = 400;
                        res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                        return;
                    }
                } else {
                    yaml_bundle = req.body;
                }

                // Install callback: delegate each document to the appropriate store
                auto install_fn = [this](const std::string& kind,
                                         const std::string& yaml_source)
                    -> std::expected<std::string, std::string> {
                    if (kind == "InstructionDefinition") {
                        if (!instruction_store_ || !instruction_store_->is_open())
                            return std::unexpected("instruction store not available");
                        // Parse YAML into InstructionDefinition and create
                        InstructionDefinition def;
                        def.name = ProductPackStore::extract_yaml_value(yaml_source, "displayName");
                        if (def.name.empty())
                            def.name = ProductPackStore::extract_yaml_value(yaml_source, "name");
                        def.version = ProductPackStore::extract_yaml_value(yaml_source, "version");
                        if (def.version.empty()) def.version = "1.0.0";
                        def.type = ProductPackStore::extract_yaml_value(yaml_source, "type");
                        if (def.type.empty()) def.type = "question";
                        def.plugin = ProductPackStore::extract_yaml_value(yaml_source, "plugin");
                        def.action = ProductPackStore::extract_yaml_value(yaml_source, "action");
                        def.description = ProductPackStore::extract_yaml_value(yaml_source, "description");
                        def.yaml_source = yaml_source;
                        def.platforms = ProductPackStore::extract_yaml_value(yaml_source, "platforms");
                        def.approval_mode = ProductPackStore::extract_yaml_value(yaml_source, "mode");
                        if (def.approval_mode.empty()) def.approval_mode = "auto";
                        return instruction_store_->create_definition(def);
                    } else if (kind == "PolicyFragment") {
                        if (!policy_store_ || !policy_store_->is_open())
                            return std::unexpected("policy store not available");
                        return policy_store_->create_fragment(yaml_source);
                    } else if (kind == "Policy") {
                        if (!policy_store_ || !policy_store_->is_open())
                            return std::unexpected("policy store not available");
                        return policy_store_->create_policy(yaml_source);
                    } else if (kind == "Workflow") {
                        if (!workflow_engine_ || !workflow_engine_->is_open())
                            return std::unexpected("workflow engine not available");
                        return workflow_engine_->create_workflow(yaml_source);
                    } else {
                        return std::unexpected("unsupported kind: " + kind);
                    }
                };

                auto result = product_pack_store_->install(yaml_bundle, install_fn);
                if (!result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                    return;
                }
                audit_log(req, "product_pack.install", "success", "product_pack", *result);
                emit_event("product_pack.installed", req, {}, {{"pack_id", *result}});
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"Product pack installed","level":"success"}})");
                res.status = 201;
                res.set_content(nlohmann::json({{"id", *result}, {"status", "installed"}}).dump(),
                                "application/json");
            });

        // GET /api/product-packs/:id — get product pack detail
        web_server_->Get(R"(/api/product-packs/([^/]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "ProductPack", "Read"))
                    return;
                if (!product_pack_store_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto id = req.matches[1].str();
                auto pack = product_pack_store_->get(id);
                if (!pack) {
                    res.status = 404;
                    res.set_content(R"({"error":{"code":404,"message":"product pack not found"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                nlohmann::json items_arr = nlohmann::json::array();
                for (const auto& item : pack->items) {
                    items_arr.push_back({{"kind", item.kind},
                                         {"item_id", item.item_id},
                                         {"name", item.name},
                                         {"yaml_source", item.yaml_source}});
                }

                res.set_content(
                    nlohmann::json({{"id", pack->id},
                                    {"name", pack->name},
                                    {"version", pack->version},
                                    {"description", pack->description},
                                    {"yaml_source", pack->yaml_source},
                                    {"items", items_arr},
                                    {"installed_at", pack->installed_at},
                                    {"verified", pack->verified}})
                        .dump(),
                    "application/json");
            });

        // DELETE /api/product-packs/:id — uninstall product pack
        web_server_->Delete(R"(/api/product-packs/([^/]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "ProductPack", "Delete"))
                    return;
                if (!product_pack_store_) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }

                auto id = req.matches[1].str();

                // Uninstall callback: delegate to the appropriate store
                auto uninstall_fn = [this](const std::string& kind,
                                           const std::string& item_id) -> bool {
                    if (kind == "InstructionDefinition") {
                        return instruction_store_ && instruction_store_->delete_definition(item_id);
                    } else if (kind == "PolicyFragment") {
                        return policy_store_ && policy_store_->delete_fragment(item_id);
                    } else if (kind == "Policy") {
                        return policy_store_ && policy_store_->delete_policy(item_id);
                    } else if (kind == "Workflow") {
                        return workflow_engine_ && workflow_engine_->delete_workflow(item_id);
                    }
                    return false;
                };

                auto result = product_pack_store_->uninstall(id, uninstall_fn);
                if (!result) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                    return;
                }
                audit_log(req, "product_pack.uninstall", "success", "product_pack", id);
                emit_event("product_pack.uninstalled", req, {}, {{"pack_id", id}});
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"Product pack uninstalled","level":"success"}})");
                res.set_content(R"({"status":"uninstalled"})", "application/json");
            });

        // -- Inventory REST endpoints (Issue 7.17) --------------------------------

        // GET /api/inventory/tables — list available inventory data types
        web_server_->Get("/api/inventory/tables",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Inventory", "Read"))
                    return;
                if (!inventory_store_ || !inventory_store_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"inventory store not available"},"meta":{"api_version":"v1"}})", "application/json");
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
        web_server_->Get(R"(/api/inventory/([^/]+)/([^/]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Inventory", "Read"))
                    return;
                if (!inventory_store_ || !inventory_store_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"inventory store not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }
                auto agent_id = req.matches[1].str();
                auto plugin = req.matches[2].str();
                auto record = inventory_store_->get(agent_id, plugin);
                if (!record) {
                    res.status = 404;
                    res.set_content(R"({"error":{"code":404,"message":"no inventory data found"},"meta":{"api_version":"v1"}})", "application/json");
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
                                                {"collected_at", record->collected_at}}).dump(),
                                "application/json");
            });

        // POST /api/inventory/query — query inventory across agents
        web_server_->Post("/api/inventory/query",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_permission(req, res, "Inventory", "Read"))
                    return;
                if (!inventory_store_ || !inventory_store_->is_open()) {
                    res.status = 503;
                    res.set_content(R"({"error":{"code":503,"message":"inventory store not available"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }
                auto body = nlohmann::json::parse(req.body, nullptr, false);
                if (body.is_discarded()) {
                    res.status = 400;
                    res.set_content(R"({"error":{"code":400,"message":"invalid JSON"},"meta":{"api_version":"v1"}})", "application/json");
                    return;
                }
                InventoryQuery q;
                q.agent_id = body.value("agent_id", "");
                q.plugin = body.value("plugin", "");
                q.since = body.value("since", int64_t{0});
                q.until = body.value("until", int64_t{0});
                q.limit = body.value("limit", 100);
                if (q.limit > 1000) q.limit = 1000;

                auto records = inventory_store_->query(q);
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& r : records) {
                    nlohmann::json data_obj;
                    try { data_obj = nlohmann::json::parse(r.data_json); }
                    catch (...) { data_obj = r.data_json; }
                    arr.push_back({{"agent_id", r.agent_id},
                                   {"plugin", r.plugin},
                                   {"data", data_obj},
                                   {"collected_at", r.collected_at}});
                }
                res.set_content(nlohmann::json({{"results", arr}, {"count", arr.size()}}).dump(),
                                "application/json");
            });

        // -- Notification REST endpoints ----------------------------------------

        // GET /api/notifications — list unread notifications
        web_server_->Get("/api/notifications",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;
                             if (!notification_store_ || !notification_store_->is_open()) {
                                 res.status = 503;
                                 res.set_content(R"({"error":{"code":503,"message":"notification store unavailable"},"meta":{"api_version":"v1"}})",
                                                 "application/json");
                                 return;
                             }
                             bool all = req.get_param_value("all") == "true";
                             int limit = 50;
                             int offset = 0;
                             auto limit_str = req.get_param_value("limit");
                             auto offset_str = req.get_param_value("offset");
                             if (!limit_str.empty()) {
                                 try { limit = std::stoi(limit_str); } catch (...) {}
                             }
                             if (!offset_str.empty()) {
                                 try { offset = std::stoi(offset_str); } catch (...) {}
                             }

                             auto notifications =
                                 all ? notification_store_->list_all(limit, offset)
                                     : notification_store_->list_unread(limit);
                             auto count = notification_store_->count_unread();

                             nlohmann::json arr = nlohmann::json::array();
                             for (const auto& n : notifications) {
                                 arr.push_back({{"id", n.id},
                                                {"timestamp", n.timestamp},
                                                {"level", n.level},
                                                {"title", n.title},
                                                {"message", n.message},
                                                {"read", n.read},
                                                {"dismissed", n.dismissed}});
                             }
                             nlohmann::json result = {{"notifications", arr},
                                                      {"unread_count", count}};
                             res.set_content(result.dump(), "application/json");
                         });

        // POST /api/notifications/:id/read — mark notification as read
        web_server_->Post(R"(/api/notifications/(\d+)/read)",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_permission(req, res, "Infrastructure", "Write"))
                                  return;
                              if (!notification_store_) {
                                  res.status = 503;
                                  res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                                  return;
                              }
                              auto id = std::stoll(req.matches[1].str());
                              notification_store_->mark_read(id);
                              res.set_content(R"({"status":"ok"})", "application/json");
                          });

        // POST /api/notifications/:id/dismiss — dismiss notification
        web_server_->Post(R"(/api/notifications/(\d+)/dismiss)",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_permission(req, res, "Infrastructure", "Write"))
                                  return;
                              if (!notification_store_) {
                                  res.status = 503;
                                  res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                                  return;
                              }
                              auto id = std::stoll(req.matches[1].str());
                              notification_store_->dismiss(id);
                              audit_log(req, "notification.dismiss", "success", "notification",
                                        std::to_string(id));
                              res.set_content(R"({"status":"ok"})", "application/json");
                          });

        // -- Webhook REST endpoints ---------------------------------------------

        // GET /api/webhooks — list all webhooks
        web_server_->Get("/api/webhooks",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;
                             if (!webhook_store_ || !webhook_store_->is_open()) {
                                 res.status = 503;
                                 res.set_content(R"({"error":{"code":503,"message":"webhook store unavailable"},"meta":{"api_version":"v1"}})",
                                                 "application/json");
                                 return;
                             }
                             auto webhooks = webhook_store_->list();
                             nlohmann::json arr = nlohmann::json::array();
                             for (const auto& w : webhooks) {
                                 arr.push_back({{"id", w.id},
                                                {"url", w.url},
                                                {"event_types", w.event_types},
                                                {"enabled", w.enabled},
                                                {"created_at", w.created_at}});
                                 // Intentionally omit secret from list response
                             }
                             res.set_content(nlohmann::json({{"webhooks", arr}}).dump(),
                                             "application/json");
                         });

        // POST /api/webhooks — create a new webhook
        web_server_->Post("/api/webhooks",
                          [this](const httplib::Request& req, httplib::Response& res) {
                              if (!require_permission(req, res, "Infrastructure", "Write"))
                                  return;
                              if (!webhook_store_ || !webhook_store_->is_open()) {
                                  res.status = 503;
                                  res.set_content(R"({"error":{"code":503,"message":"webhook store unavailable"},"meta":{"api_version":"v1"}})",
                                                  "application/json");
                                  return;
                              }
                              nlohmann::json body;
                              try {
                                  body = nlohmann::json::parse(req.body);
                              } catch (...) {
                                  res.status = 400;
                                  res.set_content(R"({"error":{"code":400,"message":"invalid JSON"},"meta":{"api_version":"v1"}})", "application/json");
                                  return;
                              }
                              auto url = body.value("url", "");
                              if (url.empty()) {
                                  res.status = 400;
                                  res.set_content(R"({"error":{"code":400,"message":"url is required"},"meta":{"api_version":"v1"}})",
                                                  "application/json");
                                  return;
                              }
                              auto event_types = body.value("event_types", "*");
                              auto secret = body.value("secret", "");
                              auto enabled = body.value("enabled", true);

                              auto id = webhook_store_->create_webhook(url, event_types, secret,
                                                                       enabled);
                              audit_log(req, "webhook.create", "success", "webhook",
                                        std::to_string(id));
                              emit_event("webhook.created", req, {},
                                         {{"webhook_id", id}, {"url", url}});
                              res.set_content(
                                  nlohmann::json({{"id", id}, {"status", "created"}}).dump(),
                                  "application/json");
                          });

        // DELETE /api/webhooks/:id — delete a webhook
        web_server_->Delete(R"(/api/webhooks/(\d+))",
                            [this](const httplib::Request& req, httplib::Response& res) {
                                if (!require_permission(req, res, "Infrastructure", "Write"))
                                    return;
                                if (!webhook_store_) {
                                    res.status = 503;
                                    res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                                    return;
                                }
                                auto id = std::stoll(req.matches[1].str());
                                if (webhook_store_->delete_webhook(id)) {
                                    audit_log(req, "webhook.delete", "success", "webhook",
                                              std::to_string(id));
                                    res.set_content(R"({"status":"deleted"})", "application/json");
                                } else {
                                    res.status = 404;
                                    res.set_content(R"({"error":{"code":404,"message":"webhook not found"},"meta":{"api_version":"v1"}})",
                                                    "application/json");
                                }
                            });

        // GET /api/webhooks/:id/deliveries — get delivery history
        web_server_->Get(R"(/api/webhooks/(\d+)/deliveries)",
                         [this](const httplib::Request& req, httplib::Response& res) {
                             if (!require_permission(req, res, "Infrastructure", "Read"))
                                 return;
                             if (!webhook_store_) {
                                 res.status = 503;
                                 res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                                 return;
                             }
                             auto webhook_id = std::stoll(req.matches[1].str());
                             int limit = 50;
                             auto limit_str = req.get_param_value("limit");
                             if (!limit_str.empty()) {
                                 try { limit = std::stoi(limit_str); } catch (...) {}
                             }
                             auto deliveries = webhook_store_->get_deliveries(webhook_id, limit);
                             nlohmann::json arr = nlohmann::json::array();
                             for (const auto& d : deliveries) {
                                 arr.push_back({{"id", d.id},
                                                {"webhook_id", d.webhook_id},
                                                {"event_type", d.event_type},
                                                {"payload", d.payload},
                                                {"status_code", d.status_code},
                                                {"delivered_at", d.delivered_at},
                                                {"error", d.error}});
                             }
                             res.set_content(nlohmann::json({{"deliveries", arr}}).dump(),
                                             "application/json");
                         });

#include "directory_patch_routes.inc"
#include "deployment_discovery_routes.inc"

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
            inventory_store_.get(),
            product_pack_store_.get(),
            sw_deploy_store_.get(),
            device_token_store_.get(),
            license_store_.get());

        // -- Register MCP server routes ----------------------------------------

        if (cfg_.mcp_disable) {
            // C8: Return a proper JSON-RPC error instead of a generic 404
            web_server_->Post("/mcp/v1/", [](const httplib::Request&, httplib::Response& res) {
                res.set_header("Content-Type", "application/json");
                res.set_content(
                    mcp::error_response_null(mcp::kMcpDisabled,
                                             "MCP is disabled on this server"),
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
                [this]() { return registry_.to_json_obj(); },
                rbac_store_.get(), instruction_store_.get(), execution_tracker_.get(),
                response_store_.get(), audit_store_.get(), tag_store_.get(),
                inventory_store_.get(), policy_store_.get(), mgmt_group_store_.get(),
                approval_manager_.get(), schedule_engine_.get(),
                cfg_.mcp_read_only, cfg_.mcp_disable);
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
            res.set_content(R"({"error":{"code":503,"message":"no agent connected"},"meta":{"api_version":"v1"}})", "application/json");
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
            res.set_content(R"({"error":{"code":503,"message":"failed to send command"},"meta":{"api_version":"v1"}})", "application/json");
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
    std::unique_ptr<mcp::McpServer> mcp_server_;

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

    // Phase 7: Inventory Store (Issue 7.17)
    std::unique_ptr<InventoryStore> inventory_store_;

    // Phase 7: Directory Sync (AD/Entra) & Patch Manager
    std::unique_ptr<DirectorySync> directory_sync_;
    std::unique_ptr<PatchManager> patch_manager_;

    // Phase 7: Deployment Jobs (Issue 7.7) & Discovery (Issue 7.18)
    std::unique_ptr<DeploymentStore> deployment_store_;
    std::unique_ptr<DiscoveryStore> discovery_store_;
    std::unique_ptr<SoftwareDeploymentStore> sw_deploy_store_;
    std::unique_ptr<DeviceTokenStore> device_token_store_;
    std::unique_ptr<LicenseStore> license_store_;

    // Fleet health aggregation
    detail::AgentHealthStore health_store_;
    std::thread health_recompute_thread_;
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> stop_entered_{false};
    std::atomic<bool> draining_{false};

    // Rate limiting
    RateLimiter api_rate_limiter_;
    RateLimiter login_rate_limiter_;
    RateLimiter mcp_rate_limiter_;
};

// -- Factory ------------------------------------------------------------------

std::unique_ptr<Server> Server::create(Config config, auth::AuthManager& auth_mgr) {
    return std::make_unique<ServerImpl>(std::move(config), auth_mgr);
}

} // namespace yuzu::server
