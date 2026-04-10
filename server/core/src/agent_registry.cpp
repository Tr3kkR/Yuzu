#include "agent_registry.hpp"

#include <algorithm>
#include <cctype>

#include "custom_properties_store.hpp"
#include "tag_store.hpp"
#include "web_utils.hpp"

namespace yuzu::server::detail {

// Bring html_escape into scope for the HTML rendering methods.
using yuzu::server::html_escape;

// -- AgentRegistry ------------------------------------------------------------

AgentRegistry::AgentRegistry(EventBus& bus, yuzu::MetricsRegistry& metrics)
    : bus_(bus), metrics_(metrics) {}

void AgentRegistry::register_agent(const pb::AgentInfo& info) {
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
        // Clean up stale session_to_agent_ entry from a prior connection
        auto old = agents_.find(info.agent_id());
        if (old != agents_.end() && !old->second->session_id.empty()) {
            session_to_agent_.erase(old->second->session_id);
        }
        agents_[info.agent_id()] = session;
    }
    metrics_.counter("yuzu_agents_registered_total").increment();
    metrics_.gauge("yuzu_agents_connected").set(static_cast<double>(agent_count()));
    bus_.publish("agent-online", info.agent_id());
    spdlog::info("Agent registered: id={}, hostname={}, plugins={}", info.agent_id(),
                 info.hostname(), info.plugins_size());
}

void AgentRegistry::set_stream(const std::string& agent_id,
                grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream,
                grpc::ServerContext* context) {
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

void AgentRegistry::clear_stream(const std::string& agent_id) {
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

void AgentRegistry::touch_activity(const std::string& agent_id) {
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

void AgentRegistry::reap_stale_sessions(std::chrono::seconds timeout) {
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

void AgentRegistry::remove_agent(const std::string& agent_id) {
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it != agents_.end()) {
            // Clean up session_to_agent_ to prevent leak
            if (!it->second->session_id.empty()) {
                session_to_agent_.erase(it->second->session_id);
            }
            agents_.erase(it);
        }
    }
    metrics_.gauge("yuzu_agents_connected").set(static_cast<double>(agent_count()));
    bus_.publish("agent-offline", agent_id);
    spdlog::info("Agent removed: id={}", agent_id);
}

void AgentRegistry::remove_agent_if_session(const std::string& agent_id,
                                            const std::string& session_id) {
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it == agents_.end() || it->second->session_id != session_id) {
            // Session doesn't match — a newer connection has taken over; do nothing
            spdlog::debug("Cleanup skipped: session mismatch for agent {} (old={}, current={})",
                          agent_id, session_id,
                          it != agents_.end() ? it->second->session_id : "<gone>");
            return;
        }
        session_to_agent_.erase(session_id);
        agents_.erase(it);
    }
    metrics_.gauge("yuzu_agents_connected").set(static_cast<double>(agent_count()));
    bus_.publish("agent-offline", agent_id);
    spdlog::info("Agent removed: id={} (session={})", agent_id, session_id);
}

void AgentRegistry::clear_stream_if_session(const std::string& agent_id,
                                            const std::string& session_id) {
    std::shared_ptr<AgentSession> session;
    {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it == agents_.end() || it->second->session_id != session_id)
            return;
        session = it->second;
    }
    {
        std::lock_guard slock(session->stream_mu);
        session->stream = nullptr;
        session->server_context = nullptr;
    }
}

void AgentRegistry::set_gateway_node(const std::string& agent_id, const std::string& node) {
    std::lock_guard lock(mu_);
    auto it = agents_.find(agent_id);
    if (it != agents_.end()) {
        it->second->gateway_node = node;
    }
}

bool AgentRegistry::send_to(const std::string& agent_id, const pb::CommandRequest& cmd) {
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
    // Gateway agent -- no local stream but agent is registered
    if (!session->gateway_node.empty()) {
        std::lock_guard glock(gw_pending_mu_);
        gw_pending_.push_back({agent_id, cmd});
        return true;
    }
    return false;
}

int AgentRegistry::send_to_all(const pb::CommandRequest& cmd) {
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

std::vector<AgentRegistry::GatewayPendingCmd> AgentRegistry::drain_gateway_pending() {
    std::lock_guard lock(gw_pending_mu_);
    auto result = std::move(gw_pending_);
    gw_pending_.clear();
    return result;
}

bool AgentRegistry::has_any() const {
    std::lock_guard lock(mu_);
    return !agents_.empty();
}

std::string AgentRegistry::display_name(const std::string& agent_id) const {
    std::lock_guard lock(mu_);
    auto it = agents_.find(agent_id);
    if (it != agents_.end() && !it->second->hostname.empty())
        return it->second->hostname;
    if (agent_id.size() > 12) return agent_id.substr(0, 12);
    return agent_id;
}

nlohmann::json AgentRegistry::to_json_obj() const {
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

std::string AgentRegistry::to_json() const { return to_json_obj().dump(); }

const std::unordered_map<std::string, std::string>& AgentRegistry::action_descriptions() {
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

std::string AgentRegistry::help_json() const {
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

std::string AgentRegistry::help_html(std::string_view filter) const {
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

    // Return data rows FIRST, OOB elements AFTER.
    // The swap target is #results-tbody (innerHTML).  If <span> OOB
    // elements appear before <tr> rows, the browser's parser rejects the
    // <span> inside <tbody> and the subsequent <tr> rows are lost.
    std::string context = filter.empty() ? "help \u2014 all plugins"
                                         : "help " + std::string(filter);
    std::string result;
    // Primary swap content: <tr> rows (valid inside <tbody>)
    result += html;
    // OOB side-effects: context label + row count (extracted by HTMX
    // regardless of position, won't break the tbody parse context)
    result += "<span id=\"result-context\" hx-swap-oob=\"innerHTML\" style=\"font-size:0.75rem;color:#8b949e\">"
              + esc(context) + "</span>";
    result += "<span id=\"row-count\" hx-swap-oob=\"innerHTML\">"
              + std::to_string(row_count) + "</span>";
    // OOB: set the thead to Plugin/Action/Description for help display
    result += "<thead id=\"results-thead\" hx-swap-oob=\"innerHTML\">"
              "<tr><th class=\"col-agent\">Plugin</th><th>Action</th><th>Description</th></tr>"
              "</thead>";
    return result;
}

std::string AgentRegistry::autocomplete_html(std::string_view query) const {
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

std::string AgentRegistry::palette_html(std::string_view query) const {
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

std::vector<std::string> AgentRegistry::all_ids() const {
    std::lock_guard lock(mu_);
    std::vector<std::string> ids;
    ids.reserve(agents_.size());
    for (const auto& id : agents_ | std::views::keys) {
        ids.push_back(id);
    }
    return ids;
}

std::string AgentRegistry::find_agent_by_stream(
    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) const {
    std::lock_guard lock(mu_);
    for (const auto& [id, s] : agents_) {
        std::lock_guard slock(s->stream_mu);
        if (s->stream == stream)
            return id;
    }
    return {};
}

std::size_t AgentRegistry::agent_count() const {
    std::lock_guard lock(mu_);
    return agents_.size();
}

void AgentRegistry::map_session(const std::string& session_id, const std::string& agent_id) {
    std::lock_guard lock(mu_);
    session_to_agent_[session_id] = agent_id;
    auto it = agents_.find(agent_id);
    if (it != agents_.end()) {
        it->second->session_id = session_id;
    }
}

std::shared_ptr<AgentSession> AgentRegistry::find_by_session(std::string_view session_id) const {
    std::lock_guard lock(mu_);
    auto sit = session_to_agent_.find(std::string(session_id));
    if (sit == session_to_agent_.end())
        return nullptr;
    auto ait = agents_.find(sit->second);
    return ait != agents_.end() ? ait->second : nullptr;
}

std::shared_ptr<AgentSession> AgentRegistry::get_session(const std::string& agent_id) const {
    std::lock_guard lock(mu_);
    auto it = agents_.find(agent_id);
    return it != agents_.end() ? it->second : nullptr;
}

std::vector<std::string> AgentRegistry::evaluate_scope(
    const yuzu::scope::Expression& expr,
    const TagStore* tag_store,
    const CustomPropertiesStore* props_store) const {
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

// -- AgentHealthStore ---------------------------------------------------------

void AgentHealthStore::upsert(const std::string& agent_id,
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

void AgentHealthStore::remove(const std::string& agent_id) {
    std::lock_guard lock(mu_);
    snapshots_.erase(agent_id);
}

void AgentHealthStore::recompute_metrics(yuzu::MetricsRegistry& metrics,
                                         std::chrono::seconds staleness) {
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

} // namespace yuzu::server::detail
