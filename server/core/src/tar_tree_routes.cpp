/// @file tar_tree_routes.cpp
/// Route registration for the TAR process-tree viewer (Frame 3 of `/tar`).
/// See tar_tree_routes.hpp for the auth/caching contract.

#include "tar_tree_routes.hpp"

#include "http_route_sink.hpp"
#include "web_utils.hpp" // html_escape, now_epoch_seconds

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <format>
#include <random>
#include <string>
#include <unordered_map>
#include <utility>

namespace yuzu::server {

namespace {

// Percent-encode for query values (mirrors device_routes' url_enc).
std::string url_enc(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            out += static_cast<char>(c);
        else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 0x0F];
        }
    }
    return out;
}

void note(httplib::Response& res, const std::string& text) {
    res.set_content("<div class=\"tar-tree-note\">" + text + "</div>", "text/html; charset=utf-8");
}

std::string get_param(const httplib::Request& req, const char* k) {
    return req.has_param(k) ? req.get_param_value(k) : std::string{};
}

// Civil date → days since 1970-01-01 (Howard Hinnant's algorithm). Used to parse a
// datetime-local value as UTC without libc timezone surprises.
std::int64_t days_from_civil(int y, unsigned m, unsigned d) {
    y -= m <= 2;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

// Accept either an epoch-seconds string (all digits) or a datetime-local value
// "YYYY-MM-DDTHH:MM[:SS]" interpreted as UTC. 0 = empty/invalid.
std::int64_t parse_ts_param(const std::string& s) {
    if (s.empty())
        return 0;
    if (std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        if (s.size() > 19)
            return 0;
        std::int64_t v = 0;
        for (char c : s)
            v = v * 10 + (c - '0');
        return v;
    }
    int Y = 0, Mo = 0, D = 0, H = 0, Mi = 0, Se = 0;
    const int n = std::sscanf(s.c_str(), "%d-%d-%dT%d:%d:%d", &Y, &Mo, &D, &H, &Mi, &Se);
    if (n < 5 || Mo < 1 || Mo > 12 || D < 1 || D > 31 || H < 0 || H > 23 || Mi < 0 || Mi > 59)
        return 0;
    return days_from_civil(Y, static_cast<unsigned>(Mo), static_cast<unsigned>(D)) * 86400 +
           H * 3600 + Mi * 60 + Se;
}

std::string random_token() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    return std::format("{:016x}{:016x}", rng(), rng());
}

// One device's OS string via the unscoped lookup (for the names-only caption).
std::string device_os(const std::optional<DeviceRow>& d) { return d ? d->os : std::string{}; }

// The server-rendered toolbar + targets (Frame-3 body). Host options come from the
// operator-scoped device list. Preset chips hx-get /run with the preset in the URL
// and the host via hx-include; the Apply chip also includes the custom inputs.
std::string render_frame(const std::vector<DeviceRow>& devices) {
    std::string h;
    h += "<div class=\"tar-tree-toolbar\">";
    // Host picker.
    h += "<select id=\"tar-tree-host\" name=\"device\" class=\"scope-chip-select\" "
         "hx-get=\"/fragments/tar/process-tree/run?preset=10m\" hx-target=\"#tar-tree\" "
         "hx-trigger=\"change\">";
    h += "<option value=\"\">Select a host\xE2\x80\xA6</option>";
    std::vector<DeviceRow> rows = devices;
    std::sort(rows.begin(), rows.end(), [](const DeviceRow& a, const DeviceRow& b) {
        return (a.hostname.empty() ? a.agent_id : a.hostname) <
               (b.hostname.empty() ? b.agent_id : b.hostname);
    });
    for (const auto& d : rows) {
        if (!d.online)
            continue;
        const std::string label = (d.hostname.empty() ? d.agent_id : d.hostname) +
                                  (d.os.empty() ? "" : (" (" + d.os + ")"));
        h += "<option value=\"" + html_escape(d.agent_id) + "\">" + html_escape(label) + "</option>";
    }
    h += "</select>";

    // Preset chips.
    const std::array<std::pair<const char*, const char*>, 6> presets = {{{"on_boot", "On boot"},
                                                                         {"on_install", "On agent install"},
                                                                         {"1m", "Last minute"},
                                                                         {"10m", "Last 10m"},
                                                                         {"1h", "Last hour"},
                                                                         {"1d", "Last day"}}};
    h += "<div class=\"tar-tree-presets\">";
    for (const auto& [tok, label] : presets) {
        h += std::string("<a class=\"tar-chip\" hx-get=\"/fragments/tar/process-tree/run?preset=") +
             tok + "\" hx-include=\"#tar-tree-host\" hx-target=\"#tar-tree\">" + label + "</a>";
    }
    h += "</div>";

    // Custom from/to (UTC) + Apply.
    h += "<div class=\"tar-tree-custom\">";
    h += "<label>From (UTC) <input id=\"tar-tree-from\" name=\"from\" type=\"datetime-local\"></label>";
    h += "<label>To (UTC) <input id=\"tar-tree-to\" name=\"to\" type=\"datetime-local\"></label>";
    h += "<a class=\"tar-chip\" hx-get=\"/fragments/tar/process-tree/run?preset=custom\" "
         "hx-include=\"#tar-tree-host,#tar-tree-from,#tar-tree-to\" hx-target=\"#tar-tree\">Apply</a>";
    h += "</div>";

    h += "</div>"; // toolbar (host + time range)

    // Filter bar — client-side state + anomalies + text filters (no round-trip;
    // re-applied after every tree swap via the htmx:afterSettle listener).
    h += "<div class=\"tar-tree-filterbar\">";
    h += "<span class=\"tt-filter-label\">Show</span>";
    h += "<a class=\"tar-chip on\" data-statechip=\"all\" onclick=\"tarTreeState('all',this)\">All</a>";
    h += "<a class=\"tar-chip\" data-statechip=\"running\" onclick=\"tarTreeState('running',this)\">"
         "Running</a>";
    h += "<a class=\"tar-chip\" data-statechip=\"exited\" onclick=\"tarTreeState('exited',this)\">"
         "Exited</a>";
    h += "<label class=\"tt-anom-toggle\"><input type=\"checkbox\" id=\"tar-tree-anom-only\" "
         "onchange=\"applyTarTreeFilters()\"> Anomalies only</label>";
    h += "<input id=\"tar-tree-filter\" class=\"tar-tree-filter\" type=\"text\" "
         "placeholder=\"Filter name / IP / PID\xE2\x80\xA6\" oninput=\"applyTarTreeFilters()\">";
    h += "</div>";

    // Two-column layout: scrollable tree on the left, a sticky always-visible detail
    // panel on the right (stacks on narrow viewports).
    h += "<div class=\"tar-tree-layout\">";
    h += "<div class=\"tar-tree-main\"><div id=\"tar-tree\"><div class=\"tar-tree-empty\">Pick a host "
         "and a timescale to reconstruct its point-in-time process tree.</div></div></div>";
    h += "<aside class=\"tar-tree-side\"><div id=\"tar-tree-detail\"><div class=\"tar-tree-mute\">"
         "Select a process to see its path, user, connections and anomaly evidence.</div></div></aside>";
    h += "</div>";
    return h;
}

// The self-re-issuing polling fragment (mirrors device live_pending).
std::string tree_pending(const std::string& device, const std::string& preset,
                         const std::string& from, const std::string& to,
                         const std::string& pcmd, const std::string& tcmd, int attempt) {
    // Explicit hx-target="this" so the poll replaces ITSELF (inside #tar-tree) and
    // never inherits an ancestor's hx-target — otherwise the outerHTML swap would
    // clobber the whole frame body, taking the toolbar with it.
    return "<div hx-get=\"/fragments/tar/process-tree/result?device=" + url_enc(device) +
           "&amp;preset=" + url_enc(preset) + "&amp;from=" + url_enc(from) + "&amp;to=" +
           url_enc(to) + "&amp;pcmd=" + url_enc(pcmd) + "&amp;tcmd=" + url_enc(tcmd) +
           "&amp;n=" + std::to_string(attempt) +
           "\" hx-trigger=\"load delay:700ms\" hx-target=\"this\" hx-swap=\"outerHTML\" "
           "class=\"tar-tree-loading\">Reconstructing the process tree\xE2\x80\xA6</div>";
}

// Poll one dispatched command for `device`: ready when it has output OR a terminal
// status. Returns {ready, output, failed, error}.
struct PollResult {
    bool ready = false;
    bool failed = false;
    std::string output;
    std::string error;
};
PollResult poll_command(const TarTreeRoutes::ResponsesFn& responses_fn, const std::string& command_id,
                        const std::string& device) {
    PollResult pr;
    if (!responses_fn)
        return pr;
    const auto rows = responses_fn(command_id);
    const DexAgentResponse* with_output = nullptr;
    const DexAgentResponse* terminal = nullptr;
    for (const auto& r : rows) {
        if (r.agent_id != device)
            continue;
        if (!r.output.empty())
            with_output = &r;
        if (r.status >= 1)
            terminal = &r;
    }
    if (with_output) {
        pr.ready = true;
        pr.output = with_output->output;
        return pr;
    }
    if (terminal) {
        pr.ready = true; // completed, possibly with no rows
        if (terminal->status >= 2) {
            pr.failed = true;
            pr.error = terminal->error_detail;
        }
        return pr;
    }
    return pr;
}

} // namespace

void TarTreeRoutes::cache_put(const std::string& token, ReconEntry entry) {
    std::lock_guard<std::mutex> lk(cache_mu_);
    const std::int64_t now = now_epoch_seconds();
    // Drop expired entries opportunistically.
    for (auto it = cache_order_.begin(); it != cache_order_.end();) {
        auto e = cache_.find(*it);
        if (e == cache_.end() || now - e->second.created > kCacheTtlSeconds) {
            if (e != cache_.end())
                cache_.erase(e);
            it = cache_order_.erase(it);
        } else {
            ++it;
        }
    }
    cache_[token] = std::move(entry);
    cache_order_.push_back(token);
    while (cache_.size() > kCacheCap && !cache_order_.empty()) {
        cache_.erase(cache_order_.front());
        cache_order_.pop_front();
    }
}

std::optional<std::string> TarTreeRoutes::cache_render_detail(const std::string& token,
                                                              std::size_t node_id,
                                                              std::string* out_device_id) {
    std::lock_guard<std::mutex> lk(cache_mu_);
    auto it = cache_.find(token);
    if (it == cache_.end())
        return std::nullopt;
    if (now_epoch_seconds() - it->second.created > kCacheTtlSeconds) {
        cache_.erase(it);
        return std::nullopt;
    }
    const ReconEntry& e = it->second;
    if (out_device_id)
        *out_device_id = e.device_id;
    if (node_id >= e.tree.nodes.size())
        return std::string("<div class=\"tar-tree-note\">That process is no longer in the "
                           "reconstruction. Re-run the tree.</div>");
    const TarProcNode& node = e.tree.nodes[node_id];
    std::vector<TarTcpConn> conns;
    for (const auto& c : e.conns)
        if (c.pid == node.pid)
            conns.push_back(c);
    std::sort(conns.begin(), conns.end(),
              [](const TarTcpConn& a, const TarTcpConn& b) { return a.ts > b.ts; });
    return render_tar_proc_detail(node, conns, e.os);
}

void TarTreeRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                    ScopedPermFn scoped_perm_fn, DevicesFn devices_fn,
                                    LookupFn lookup_fn, DispatchFn dispatch_fn,
                                    ResponsesFn responses_fn, AuditFn audit_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(scoped_perm_fn),
                    std::move(devices_fn), std::move(lookup_fn), std::move(dispatch_fn),
                    std::move(responses_fn), std::move(audit_fn));
}

void TarTreeRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                    ScopedPermFn scoped_perm_fn, DevicesFn devices_fn,
                                    LookupFn lookup_fn, DispatchFn dispatch_fn,
                                    ResponsesFn responses_fn, AuditFn audit_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    devices_fn_ = std::move(devices_fn);
    lookup_fn_ = std::move(lookup_fn);
    dispatch_fn_ = std::move(dispatch_fn);
    responses_fn_ = std::move(responses_fn);
    audit_fn_ = std::move(audit_fn);

    // Soft Execute probe (htmx swallows a raw 403 → render an in-panel note instead).
    auto can_execute = [this](const httplib::Request& req, const std::string& id) {
        httplib::Response probe;
        return scoped_perm_fn_ && scoped_perm_fn_(req, probe, "Execution", "Execute", id);
    };

    // -- Frame body: toolbar + targets (host list is operator-scoped). --
    sink.Get("/fragments/tar/process-tree", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        if (!perm_fn_(req, res, "Infrastructure", "Read"))
            return;
        std::vector<DeviceRow> devices =
            devices_fn_ ? devices_fn_(session->username) : std::vector<DeviceRow>{};
        res.set_content(render_frame(devices), "text/html; charset=utf-8");
    });

    // -- Run: scope + execute gate -> dispatch two canned tar.sql -> poll fragment. --
    sink.Get("/fragments/tar/process-tree/run", [this, can_execute](const httplib::Request& req,
                                                                    httplib::Response& res) {
        const std::string device = get_param(req, "device");
        const std::string preset = get_param(req, "preset");
        const std::string from = get_param(req, "from");
        const std::string to = get_param(req, "to");
        if (device.empty()) {
            note(res, "Select a host to reconstruct its process tree.");
            return;
        }
        // Per-device scoped Read floor (tier + management group).
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", device))
            return;
        if (!can_execute(req, device)) {
            note(res, "Reconstructing the tree dispatches a read-only query to the device and "
                      "needs the <b>Execute</b> permission.");
            return;
        }
        if (!dispatch_fn_ || !responses_fn_) {
            note(res, "Live device query is unavailable on this server.");
            return;
        }
        // SQL fetch is bounded only at the TOP (ts <= to) for a custom `to`; the lower
        // bound stays oldest-retained so a long-running process started before the
        // window is still captured (the engine applies `from` as an interval filter).
        std::int64_t fetch_to = 0;
        if (preset == "custom")
            fetch_to = parse_ts_param(to);
        const std::string where = fetch_to > 0 ? std::format(" WHERE ts <= {}", fetch_to) : "";
        const std::string psql =
            "SELECT ts, action, pid, ppid, name, cmdline, user FROM $Process_Live" + where +
            " ORDER BY ts DESC LIMIT 100000";
        const std::string tsql =
            "SELECT pid, process_name, proto, local_port, remote_addr, remote_port, state, ts, "
            "action FROM $TCP_Live" +
            where + " ORDER BY ts DESC LIMIT 5000";
        const auto [pcmd, psent] = dispatch_fn_("tar", "sql", {device}, "", {{"sql", psql}});
        const auto [tcmd, tsent] = dispatch_fn_("tar", "sql", {device}, "", {{"sql", tsql}});
        (void)tsent;
        if (psent == 0) {
            note(res, "Device offline \xE2\x80\x94 the process tree needs a connected agent.");
            return;
        }
        res.set_content(tree_pending(device, preset, from, to, pcmd, tcmd, 1),
                        "text/html; charset=utf-8");
    });

    // -- Result: poll both commands -> reconstruct -> cache -> render tree. --
    sink.Get("/fragments/tar/process-tree/result", [this, can_execute](const httplib::Request& req,
                                                                        httplib::Response& res) {
        const std::string device = get_param(req, "device");
        const std::string preset = get_param(req, "preset");
        const std::string from = get_param(req, "from");
        const std::string to = get_param(req, "to");
        const std::string pcmd = get_param(req, "pcmd");
        const std::string tcmd = get_param(req, "tcmd");
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", device))
            return;
        if (!can_execute(req, device)) {
            note(res, "Live device query needs the <b>Execute</b> permission.");
            return;
        }
        // Only tar.sql commands for the named agent are pollable here.
        if (device.empty() || pcmd.size() > 64 || tcmd.size() > 64 ||
            !pcmd.starts_with("tar-") || !tcmd.starts_with("tar-")) {
            res.status = 400;
            res.set_content("bad request", "text/plain");
            return;
        }
        if (!responses_fn_) {
            note(res, "Live device query is unavailable on this server.");
            return;
        }
        constexpr int kMaxAttempts = 40; // ~28s at 700ms
        int attempt = 1;
        if (req.has_param("n")) {
            try {
                attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 60);
            } catch (...) {
            }
        }
        const PollResult proc = poll_command(responses_fn_, pcmd, device);
        const PollResult tcp = poll_command(responses_fn_, tcmd, device);
        if (!proc.ready || !tcp.ready) {
            if (attempt >= kMaxAttempts) {
                note(res, "No response from the device (timed out) \xE2\x80\x94 it may have gone "
                          "offline. Re-run to retry.");
                return;
            }
            res.set_content(tree_pending(device, preset, from, to, pcmd, tcmd, attempt + 1),
                            "text/html; charset=utf-8");
            return;
        }
        if (proc.failed) {
            note(res, "The device failed the process query: " + html_escape(proc.error.substr(0, 200)));
            return;
        }
        if (proc.output.starts_with("error|")) {
            note(res, "The device reported an error: " + html_escape(proc.output.substr(6, 200)));
            return;
        }

        auto events = parse_tar_process_output(proc.output);
        auto conns = tcp.failed ? std::vector<TarTcpConn>{} : parse_tar_tcp_output(tcp.output);
        const auto anchors = compute_tar_anchors(events);
        const std::int64_t now = now_epoch_seconds();
        const TarWindow win =
            resolve_tar_window(preset, parse_ts_param(from), parse_ts_param(to), anchors, now);
        auto tree = reconstruct_tar_process_tree(events, win.from_ts, win.to_ts, anchors);

        const std::string os = device_os(lookup_fn_ ? lookup_fn_(device) : std::nullopt);
        const std::string token = random_token();
        const int node_count = tree.running_count + tree.exited_count;
        const int anomaly_count = tree.anomaly_count;

        // Full tree, rendered once; running/exited/anomalies/text filtering is applied
        // client-side from the toolbar (each row carries data-state/data-anom), so a
        // filter toggle needs no re-dispatch.
        std::string body = render_tar_tree_fragment(tree, conns, device, token, os);

        ReconEntry entry;
        entry.device_id = device;
        entry.os = os;
        entry.conns = std::move(conns);
        entry.tree = std::move(tree);
        entry.created = now;
        cache_put(token, std::move(entry));

        if (audit_fn_)
            audit_fn_(req, "tar.process_tree.read", "success", "Agent", device,
                      std::format("preset={} from={} to={} nodes={} anomalies={}",
                                  preset.empty() ? "10m" : preset, win.from_ts, win.to_ts,
                                  node_count, anomaly_count));
        res.set_content(body, "text/html; charset=utf-8");
    });

    // -- Detail: render one node from the cached reconstruction (re-checks scope). --
    sink.Get("/fragments/tar/process-tree/detail", [this](const httplib::Request& req,
                                                          httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        const std::string token = get_param(req, "token");
        std::size_t node_id = 0;
        try {
            node_id = static_cast<std::size_t>(std::stoul(get_param(req, "node")));
        } catch (...) {
            res.status = 400;
            res.set_content("bad request", "text/plain");
            return;
        }
        if (token.size() != 32 ||
            !std::all_of(token.begin(), token.end(), [](char c) { return std::isxdigit(static_cast<unsigned char>(c)); })) {
            res.status = 400;
            res.set_content("bad request", "text/plain");
            return;
        }
        // Resolve the cached device first (without rendering), then re-check the
        // SCOPED Read on it — a leaked token must not cross management scope.
        std::string device_id;
        {
            std::lock_guard<std::mutex> lk(cache_mu_);
            auto it = cache_.find(token);
            if (it != cache_.end())
                device_id = it->second.device_id;
        }
        if (device_id.empty()) {
            note(res, "The reconstruction expired. Re-run the tree.");
            return;
        }
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", device_id))
            return;
        auto html = cache_render_detail(token, node_id, nullptr);
        if (!html) {
            note(res, "The reconstruction expired. Re-run the tree.");
            return;
        }
        res.set_content(*html, "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
