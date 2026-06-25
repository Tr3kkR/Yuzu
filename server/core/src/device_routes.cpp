/// @file device_routes.cpp
/// Route registration for the shared device surfaces — `/devices` (list) +
/// `/device?id=` (the entity page) page shells, and the read-only HTMX fragments.
/// Renderers live in device_ui.cpp. SLICE 1 is auth-only (matches the current
/// agent-list posture); later slices add the perm/privacy gates for the behavioural
/// DEX lens + the live pull (see device_routes.hpp header).

#include "device_routes.hpp"

#include "dex_routes.hpp"             // dex_device_score, dex_iso_since
#include "live_kinds.hpp"             // shared live-read kind table + parser (S2)
#include "guaranteed_state_store.hpp" // dex_device_signal_summary, agent_rule_statuses, list_rules
#include "http_route_sink.hpp"
#include "rest_audit.hpp"             // detail::emit_behavioral_audit (Sec-Audit-Failed, #1647)
#include "web_utils.hpp"              // html_escape

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// Shared full-page shell (global scope, defined in guardian_page_ui.cpp).
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Render the shared page shell with the title + initial fragment substituted, and
// the default-active Guardian nav item de-activated (these pages are cross-cutting,
// not under Guardian). Mirrors NetworkRoutes' shell handling.
std::string page_shell(const std::string& title, const std::string& fragment_url) {
    std::string html(kGuardianDetailPageHtml);
    auto sub = [&](const std::string& tok, const std::string& val) {
        for (auto p = html.find(tok); p != std::string::npos; p = html.find(tok, p + val.size()))
            html.replace(p, tok.size(), val);
    };
    sub("{{TITLE}}", title);
    sub("{{FRAGMENT}}", fragment_url);
    sub("<a href=\"/guardian\" class=\"nav-link active\">Guardian</a>",
        "<a href=\"/guardian\" class=\"nav-link\">Guardian</a>");
    return html;
}

bool matches(const DeviceRow& d, const std::string& q) {
    if (q.empty()) return true;
    std::string hay = to_lower(d.hostname + " " + d.agent_id + " " + d.os + " " + d.arch + " " +
                               d.segment);
    for (const auto& t : d.tags) hay += " " + to_lower(t);
    return hay.find(q) != std::string::npos;
}

using yuzu::server::live::LiveKind;

// Dashboard live-read kind table. The two shared kinds (uptime, processes) delegate to
// the shared live_kinds.hpp table so the dashboard and the REST sibling can't drift on
// them (governance S2). The dashboard ALSO offers richer multi-card kinds — the
// process tree (with a SECOND network_diag/connections dispatch joined by PID) plus the
// services / users / network / capture-source cards — that the REST surface does not
// yet render (A1 backfill, #1649). `kind` is an ALLOWLIST token validated before it
// drives any dispatch or reaches markup; each kind carries its own `device.live.<kind>`
// audit verb so usage-class reads stay separately countable for works-council.
std::optional<LiveKind> resolve_live_kind(const std::string& kind) {
    if (kind == "uptime" || kind == "processes")
        return yuzu::server::live::resolve_kind(kind); // shared table (REST parity)
    if (kind == "process_tree") // tree + hash; joins live connections by pid (Windows)
        return LiveKind{"processes",     "list_tree", "Processes", "device.live.process_tree",
                        "network_diag", "connections"};
    if (kind == "services")
        return LiveKind{"services", "list", "Services", "device.live.services"};
    if (kind == "users")
        return LiveKind{"users", "logged_on", "Logged-in users", "device.live.users"};
    if (kind == "netconfig")
        return LiveKind{"network_config", "ip_addresses", "Adapters & IP", "device.live.netconfig"};
    if (kind == "arp")
        return LiveKind{"network_config", "arp", "ARP", "device.live.arp"};
    if (kind == "dns_cache")
        return LiveKind{"network_config", "dns_cache", "DNS cache", "device.live.dns_cache"};
    if (kind == "listening")
        return LiveKind{"network_diag", "listening", "Listening ports", "device.live.listening"};
    if (kind == "connections")
        return LiveKind{"network_diag", "connections", "Active connections",
                        "device.live.connections"};
    if (kind == "capture_sources")
        return LiveKind{"tar", "status", "Capture sources", "device.live.capture_sources"};
    return std::nullopt;
}

// Split one pipe-delimited line into fields (empty trailing field preserved).
std::vector<std::string> pipe_fields(const std::string& line) {
    std::vector<std::string> f;
    std::size_t p = 0;
    while (true) {
        const auto q = line.find('|', p);
        f.push_back(line.substr(p, q == std::string::npos ? std::string::npos : q - p));
        if (q == std::string::npos) break;
        p = q + 1;
    }
    return f;
}

// An htmx out-of-band swap that fills a card count-badge / KPI tile already in the DOM.
// `cls` matches the placeholder element's class so styling survives the swap.
std::string oob(const std::string& id, const std::string& cls, const std::string& text) {
    return "<span class=\"" + cls + "\" id=\"" + id + "\" hx-swap-oob=\"true\">" + text + "</span>";
}

// Bound on parsed rows per source — a forged/huge response can shrink the rendered set
// but never blow up memory or produce an unrenderable card (SRE finding).
constexpr std::size_t kMaxLiveRows = 20000;

// Parse the agent output for `kind` into its typed rows and render the card body,
// appending the OOB count-badge + KPI updates. `output2` carries the optional joined
// dataset (process_tree's connections). uptime/processes use the shared live_kinds.hpp
// parsers (REST parity); the rest parse the dashboard-only wire shapes inline. All
// agent fields are HTML-escaped at render.
std::string render_live_result(const std::string& kind, const LiveKind& lk,
                               const std::string& output, const std::string& output2) {
    const auto lines = yuzu::server::live::split_lines(output);

    if (kind == "uptime") { // KPI-only (the shell's hidden loader fills the Uptime KPI)
        const auto u = yuzu::server::live::parse_uptime(output);
        const std::string v = u.display.value_or("");
        return oob("ls-kpi-uptime", "n", v.empty() ? "&mdash;" : html_escape(v));
    }

    if (kind == "processes") { // legacy flat hashed list (retained for REST/scripted callers)
        std::vector<LiveProcess> procs;
        for (const auto& p : yuzu::server::live::parse_processes(output))
            procs.push_back(LiveProcess{static_cast<int>(p.pid), p.name, p.sha256, p.path});
        return render_device_live_processes(procs);
    }

    if (kind == "process_tree") { // proc|pid|ppid|name|sha256|path (+ conn| join)
        std::vector<LiveProcNode> nodes;
        for (const auto& l : lines) {
            if (!l.starts_with("proc|")) continue;
            auto f = pipe_fields(l);
            if (f.size() < 4) continue;
            LiveProcNode n;
            // Guard the 64-bit-unsigned-long → uint32 narrowing: a forged pid/ppid
            // above UINT32_MAX would otherwise truncate (e.g. 2^32 → 0) and collide
            // with the "ppid==0 ⇒ root" sentinel, corrupting parent→child attribution.
            try { unsigned long v = std::stoul(f[1]); if (v > 0xFFFFFFFFUL) continue; n.pid = static_cast<std::uint32_t>(v); }
            catch (...) { continue; }
            try { unsigned long v = std::stoul(f[2]); n.ppid = (v > 0xFFFFFFFFUL) ? 0u : static_cast<std::uint32_t>(v); }
            catch (...) { n.ppid = 0; }
            n.name = f[3];
            if (f.size() > 4) n.sha256 = f[4];
            if (f.size() > 5) n.path = f[5];
            nodes.push_back(std::move(n));
            if (nodes.size() >= kMaxLiveRows) break;
        }
        std::vector<LiveConn> conns;
        for (const auto& l : yuzu::server::live::split_lines(output2)) {
            if (!l.starts_with("conn|")) continue; // conn|tcp|lip|lport|rip|rport|pid (Windows)
            auto f = pipe_fields(l);
            if (f.size() < 7) continue;
            LiveConn c;
            // Guard the uint32 narrowing exactly as the node-pid parse above: a forged
            // pid > UINT32_MAX must not silently truncate (and on LP64 std::stoul would
            // not throw). Match the sibling so the join key can't collide via truncation.
            try { unsigned long v = std::stoul(f[6]); if (v > 0xFFFFFFFFUL) continue; c.pid = static_cast<std::uint32_t>(v); }
            catch (...) { continue; }
            c.remote_addr = f[4];
            try { c.remote_port = std::stoi(f[5]); } catch (...) {}
            try { c.local_port = std::stoi(f[3]); } catch (...) {}
            conns.push_back(std::move(c));
            if (conns.size() >= kMaxLiveRows) break;
        }
        std::string body = render_device_live_tree(nodes, conns);
        body += oob("ls-cnt-process_tree", "ls-cnt", std::to_string(nodes.size()));
        body += oob("ls-kpi-procs", "n", std::to_string(nodes.size()));
        return body;
    }

    if (kind == "services") { // Windows: svc|name|display|status|startup; Linux: svc|name|status|desc
        std::vector<LiveService> rows;
        int running = 0;
        for (const auto& l : lines) {
            if (!l.starts_with("svc|")) continue;
            auto f = pipe_fields(l);
            LiveService s;
            if (f.size() >= 5) { // Windows: svc|name|display|status|startup
                s.name = f[1]; s.display = f[2]; s.status = f[3]; s.startup = f[4];
            } else if (f.size() == 4) {
                // Two distinct 4-field shapes share this arity: Linux svc|name|status|description
                // and macOS svc|label|pid|status. Disambiguate on the numeric pid column so the
                // macOS State cell shows the status, not the PID (consistency B1).
                s.name = f[1];
                const bool macos = !f[2].empty() && std::all_of(f[2].begin(), f[2].end(), [](unsigned char ch) {
                    return std::isdigit(ch) != 0;
                });
                if (macos) { s.status = f[3]; }            // svc|label|pid|status
                else { s.status = f[2]; s.display = f[3]; } // svc|name|status|description
            } else {
                continue;
            }
            std::string st = s.status;
            for (char& c : st) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (st.find("run") != std::string::npos) ++running;
            rows.push_back(std::move(s));
            if (rows.size() >= kMaxLiveRows) break;
        }
        std::string body = render_device_live_services(rows);
        body += oob("ls-cnt-services", "ls-cnt",
                    std::to_string(rows.size()) + " &middot; " + std::to_string(running) + " run");
        body += oob("ls-kpi-svc", "n", std::to_string(running));
        return body;
    }

    if (kind == "users") { // user|user|host|logon_type|tty
        std::vector<LiveUserRow> rows;
        for (const auto& l : lines) {
            if (!l.starts_with("user|")) continue;
            auto f = pipe_fields(l);
            if (f.size() < 2) continue;
            LiveUserRow u;
            u.user = f[1];
            if (f.size() > 2) u.host = f[2];
            if (f.size() > 3) u.logon_type = f[3];
            if (f.size() > 4) u.session = f[4];
            rows.push_back(std::move(u));
            if (rows.size() >= kMaxLiveRows) break;
        }
        std::string body = render_device_live_users(rows);
        body += oob("ls-cnt-users", "ls-cnt", std::to_string(rows.size()));
        body += oob("ls-kpi-users", "n", std::to_string(rows.size()));
        return body;
    }

    if (kind == "netconfig") { // ip|adapter|addr|prefix|gateway
        std::vector<LiveNetAddr> rows;
        for (const auto& l : lines) {
            if (!l.starts_with("ip|")) continue;
            auto f = pipe_fields(l);
            if (f.size() < 3) continue;
            LiveNetAddr a;
            a.adapter = f[1];
            a.ip = f[2];
            if (f.size() > 3) { try { a.prefix = std::stoi(f[3]); } catch (...) {} }
            if (f.size() > 4 && f[4] != "-" && f[4] != "0.0.0.0") a.gateway = f[4];
            rows.push_back(std::move(a));
            if (rows.size() >= kMaxLiveRows) break;
        }
        std::string body = render_device_live_netconfig(rows);
        body += oob("ls-cnt-netconfig", "ls-cnt", std::to_string(rows.size()));
        return body;
    }

    if (kind == "arp") { // arp|iface|ip|mac|type
        std::vector<LiveArpEntry> rows;
        for (const auto& l : lines) {
            if (!l.starts_with("arp|")) continue;
            auto f = pipe_fields(l);
            if (f.size() < 5) continue;
            LiveArpEntry a{f[1], f[2], (f[3] == "-" ? "" : f[3]), f[4]};
            rows.push_back(std::move(a));
            if (rows.size() >= kMaxLiveRows) break;
        }
        std::string body = render_device_live_arp(rows);
        body += oob("ls-cnt-arp", "ls-cnt", std::to_string(rows.size()));
        return body;
    }

    if (kind == "dns_cache") { // cache_entry|name|type|...
        std::vector<LiveDnsEntry> rows;
        for (const auto& l : lines) {
            if (!l.starts_with("cache_entry|")) continue;
            auto f = pipe_fields(l);
            if (f.size() < 3 || f[1] == "not_available") continue;
            rows.push_back(LiveDnsEntry{f[1], f[2]});
            if (rows.size() >= kMaxLiveRows) break;
        }
        std::string body = render_device_live_dns(rows);
        body += oob("ls-cnt-dns_cache", "ls-cnt", std::to_string(rows.size()));
        return body;
    }

    if (kind == "listening") { // listen|tcp|ip|port|pid
        std::vector<LiveListen> rows;
        for (const auto& l : lines) {
            if (!l.starts_with("listen|")) continue;
            auto f = pipe_fields(l);
            if (f.size() < 4) continue;
            LiveListen s;
            s.proto = f[1];
            s.ip = f[2];
            try { s.port = std::stoi(f[3]); } catch (...) {}
            if (f.size() > 4) { try { s.pid = std::stoll(f[4]); } catch (...) {} }
            rows.push_back(std::move(s));
            if (rows.size() >= kMaxLiveRows) break;
        }
        std::string body = render_device_live_listening(rows);
        body += oob("ls-cnt-listening", "ls-cnt", std::to_string(rows.size()));
        body += oob("ls-kpi-listen", "n", std::to_string(rows.size()));
        return body;
    }

    if (kind == "connections") { // conn|tcp|lip|lport|rip|rport|pid
        std::vector<LiveConnRow> rows;
        for (const auto& l : lines) {
            if (!l.starts_with("conn|")) continue;
            auto f = pipe_fields(l);
            if (f.size() < 6) continue;
            LiveConnRow c;
            c.proto = f[1];
            c.local = f[2] + ":" + f[3];
            c.remote = f[4] + ":" + f[5];
            c.state = "ESTABLISHED"; // network_diag/connections emits established only
            rows.push_back(std::move(c));
            if (rows.size() >= kMaxLiveRows) break;
        }
        std::string body = render_device_live_connections(rows);
        body += oob("ls-cnt-connections", "ls-cnt", std::to_string(rows.size()));
        body += oob("ls-kpi-conn", "n", std::to_string(rows.size()));
        return body;
    }

    if (kind == "capture_sources") { // tar status: config|<src>_enabled|v, config|<src>_live_rows|N
        // Display order + presentation metadata. The server does NOT link the agent's
        // tar_schema_registry, so source name/$-table/category are held here; we only
        // render a row for a source the agent actually reported (its `<src>_enabled` key
        // is present in tar/status), so an older agent without arp/dns shows no phantom
        // rows. Hand-maintained — the os-capability-matrix "will drift; durable fix =
        // generate from machine-readable metadata" situation, tracked as a follow-up.
        struct Meta { const char* name; const char* dollar; const char* category; };
        static const Meta kSrc[] = {
            {"process", "Process", "Activity"},  {"tcp", "TCP", "Network"},
            {"service", "Service", "Inventory"}, {"user", "User", "Identity"},
            {"perf", "Perf", "Performance"},     {"procperf", "ProcPerf", "Performance"},
            {"netqual", "NetQual", "Network"},   {"module", "Module", "Inventory"},
            {"arp", "ARP", "Network"},           {"dns", "DNS", "Network"}};
        std::unordered_map<std::string, std::string> cfg;
        for (const auto& l : lines) {
            if (!l.starts_with("config|")) continue;
            auto f = pipe_fields(l); // config|<key>|<value>
            if (f.size() >= 3) cfg[f[1]] = f[2];
        }
        std::vector<LiveCaptureSource> rows;
        int on = 0;
        for (const auto& m : kSrc) {
            auto en = cfg.find(std::string(m.name) + "_enabled");
            if (en == cfg.end())
                continue; // agent did not report this source (older agent / not built) — no phantom row
            LiveCaptureSource s;
            s.name = m.name;
            s.dollar = m.dollar;
            s.category = m.category;
            s.enabled = (en->second == "true");
            if (auto it = cfg.find(std::string(m.name) + "_live_rows"); it != cfg.end()) {
                try { s.live_rows = std::stoll(it->second); } catch (...) {}
            }
            if (s.enabled) ++on;
            rows.push_back(std::move(s));
        }
        std::string body = render_device_live_capture_sources(rows);
        body += oob("ls-cnt-capture_sources", "ls-cnt",
                    std::to_string(on) + " of " + std::to_string(rows.size()) + " on");
        return body;
    }

    return "<div class=\"gp-note\">Unsupported live result.</div>";
}

} // namespace

void DeviceRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                   ScopedPermFn scoped_perm_fn, DevicesFn devices_fn,
                                   LookupFn lookup_fn, const GuaranteedStateStore* store,
                                   DispatchFn dispatch_fn, ResponsesFn responses_fn,
                                   AuditFn audit_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(scoped_perm_fn),
                    std::move(devices_fn), std::move(lookup_fn), store, std::move(dispatch_fn),
                    std::move(responses_fn), std::move(audit_fn));
}

void DeviceRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                   ScopedPermFn scoped_perm_fn, DevicesFn devices_fn,
                                   LookupFn lookup_fn, const GuaranteedStateStore* store,
                                   DispatchFn dispatch_fn, ResponsesFn responses_fn,
                                   AuditFn audit_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    devices_fn_ = std::move(devices_fn);
    lookup_fn_ = std::move(lookup_fn);
    store_ = store;
    dispatch_fn_ = std::move(dispatch_fn);
    responses_fn_ = std::move(responses_fn);
    audit_fn_ = std::move(audit_fn);

    // -- /devices page shell (auth-only static chrome) --
    sink.Get("/devices", [this](const httplib::Request& req, httplib::Response& res) {
        if (!auth_fn_(req, res)) {
            res.set_redirect("/login");
            return;
        }
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(page_shell("Yuzu \xE2\x80\x94 Devices", "/fragments/devices/list"),
                        "text/html; charset=utf-8");
    });

    // -- /device?id= page shell (auth-only) --
    sink.Get("/device", [this](const httplib::Request& req, httplib::Response& res) {
        if (!auth_fn_(req, res)) {
            res.set_redirect("/login");
            return;
        }
        std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // The shell hx-loads the page-body fragment (which carries the id forward).
        std::string frag = "/fragments/device/page";
        if (!id.empty()) {
            // Minimal query-safe echo; the fragment handler re-reads `id` from params.
            std::string enc;
            static const char* kHex = "0123456789ABCDEF";
            for (unsigned char c : id) {
                if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                    enc += static_cast<char>(c);
                else { enc += '%'; enc += kHex[c >> 4]; enc += kHex[c & 0x0F]; }
            }
            frag += "?id=" + enc;
        }
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(page_shell("Yuzu \xE2\x80\x94 Device", frag), "text/html; charset=utf-8");
    });

    // -- /fragments/devices/list — global Infrastructure:Read + per-operator scope.
    // Exact /api/agents parity: the gate admits Infrastructure:Read operators and
    // the provider (get_visible_agents_json) returns only the caller's visible
    // devices, so an operator never enumerates devices outside their scope. --
    sink.Get("/fragments/devices/list", [this](const httplib::Request& req,
                                               httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        if (!perm_fn_(req, res, "Infrastructure", "Read")) return;
        std::vector<DeviceRow> all =
            devices_fn_ ? devices_fn_(session->username) : std::vector<DeviceRow>{};
        const std::string q = to_lower(req.has_param("q") ? req.get_param_value("q") : "");
        std::string os = req.has_param("os") ? req.get_param_value("os") : "all";
        std::string status = req.has_param("status") ? req.get_param_value("status") : "all";
        if (os.empty()) os = "all";
        if (status.empty()) status = "all";

        std::size_t total = all.size();
        std::size_t online = static_cast<std::size_t>(
            std::count_if(all.begin(), all.end(), [](const DeviceRow& d) { return d.online; }));

        std::vector<DeviceRow> rows;
        for (auto& d : all) {
            if (os != "all" && to_lower(d.os) != to_lower(os) &&
                !(os == "macos" && (d.os == "darwin")))
                continue;
            if (status == "online" && !d.online) continue;
            if (status == "offline" && d.online) continue;
            if (!matches(d, q)) continue;
            rows.push_back(d);
        }
        std::sort(rows.begin(), rows.end(), [](const DeviceRow& a, const DeviceRow& b) {
            return (a.hostname.empty() ? a.agent_id : a.hostname) <
                   (b.hostname.empty() ? b.agent_id : b.hostname);
        });
        // Score ONLY the rows we render (post-filter) — devices_fn_ no longer
        // scores the fleet, so a filtered/searched list never pays for the
        // devices it excludes. (Fleet-scale pagination of this set is a tracked
        // follow-up; the win here is killing the score-all-then-filter waste.)
        if (store_) {
            const std::string since = dex_iso_since(7);
            for (auto& d : rows)
                d.dex_score = dex_device_score(store_, d.agent_id, since);
        }
        res.set_content(render_devices_list_fragment(rows, req.has_param("q") ? req.get_param_value("q") : "",
                                                     os, status, online, total),
                        "text/html; charset=utf-8");
    });

    // Resolve one device's identity row, UNSCOPED. Authz is the scoped_perm_fn_ gate
    // each per-device route runs FIRST; this is the post-authz row fetch. It must NOT
    // re-scope (see LookupFn doc: list scoping is non-ancestor, the gate is
    // ancestor-aware — re-scoping here would 404 a parent-group-authorized device).
    auto get_one = [this](const std::string& id) -> std::optional<DeviceRow> {
        return lookup_fn_ ? lookup_fn_(id) : std::nullopt;
    };

    // -- /fragments/device/page (the full page body: identity + lens tabs + lens) --
    sink.Get("/fragments/device/page", [this, get_one](const httplib::Request& req,
                                                       httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // Per-device scope: Infrastructure:Read for THIS device (tier + management
        // group, ancestor-aware). 403 = outside scope; an in-scope-but-absent device
        // falls through to the honest not-found body below.
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", id)) return;
        auto d = get_one(id);
        // Score ONLY this device — devices_fn_ no longer scores the fleet (a page
        // open must not pay an N-device cost; the score badge needs just this one).
        if (d && store_)
            d->dex_score = dex_device_score(store_, d->agent_id, dex_iso_since(7));
        res.set_content(d ? render_device_page(*d) : render_device_not_found(id),
                        "text/html; charset=utf-8");
    });

    // -- /fragments/device/info (the Device-info lens, for tab switching) --
    sink.Get("/fragments/device/info", [this, get_one](const httplib::Request& req,
                                                       httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) { res.status = 401; res.set_content("auth required", "text/plain"); return; }
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (!scoped_perm_fn_(req, res, "Infrastructure", "Read", id)) return; // per-device scope
        auto d = get_one(id);
        res.set_content(d ? render_device_info_fragment(*d) : render_device_not_found(id),
                        "text/html; charset=utf-8");
    });

    // -- DEX lens: per-device score + signal summary (+ link to the full drill) --
    sink.Get("/fragments/device/dex", [this](const httplib::Request& req, httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // Per-device behavioral data (PII): GuaranteedState:Read SCOPED to this
        // device (tier + management group) + audit-on-open. Stronger than the
        // sibling /fragments/dex/device's bare Read gate — closes the cross-scope
        // read of another team's per-device DEX summary.
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        if (!store_) {
            res.set_content(render_device_lens_placeholder("dex", id, "DEX store unavailable."),
                            "text/html; charset=utf-8");
            return;
        }
        // Behavioural-PII access audit. HTML dashboard fragment → set-and-proceed:
        // a dropped evidence row flags via Sec-Audit-Failed but STILL renders, so
        // a transient audit hiccup never blanks the operator's lens (#1647). The
        // shared helper captures the persist bool behind a try/catch (the throw
        // arm is otherwise silent) — one pattern across every behavioural route.
        (void)detail::emit_behavioral_audit(audit_fn_, req, res, "dex.device.view", "success",
                                            "Agent", id,
                                            "device DEX lens (per-device signal summary)");
        const std::string since = dex_iso_since(7);
        const int score = dex_device_score(store_, id, since);
        std::vector<std::pair<std::string, std::int64_t>> sigs;
        for (const auto& s : store_->dex_device_signal_summary(id, since))
            sigs.emplace_back(s.obs_type, s.count);
        res.set_content(render_device_dex_lens(id, score, sigs), "text/html; charset=utf-8");
    });
    // -- Guardian lens: per-guard compliance state for this device --
    sink.Get("/fragments/device/guardian", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // Per-device compliance state: GuaranteedState:Read SCOPED to this device
        // (tier + management group) + audit-on-open (parity with the DEX lens above).
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        if (!store_) {
            res.set_content(render_device_lens_placeholder("guardian", id, "Guardian store unavailable."),
                            "text/html; charset=utf-8");
            return;
        }
        // Behavioural-PII access audit — set-and-proceed (HTML fragment), parity
        // with the DEX lens above and the shared #1647 helper.
        (void)detail::emit_behavioral_audit(audit_fn_, req, res, "guardian.device.view", "success",
                                            "Agent", id,
                                            "device Guardian lens (per-guard compliance)");
        std::unordered_map<std::string, std::string> rule_names;
        for (const auto& r : store_->list_rules())
            rule_names[r.rule_id] = r.name;
        std::vector<DeviceGuardRow> guards;
        for (const auto& st : store_->agent_rule_statuses()) { // all; filter to this agent
            if (st.agent_id != id)
                continue;
            DeviceGuardRow g;
            auto it = rule_names.find(st.rule_id);
            g.name = (it != rule_names.end() && !it->second.empty()) ? it->second : st.rule_id;
            g.state = st.state;
            g.updated_at = st.updated_at;
            guards.push_back(std::move(g));
        }
        res.set_content(render_device_guardian_lens(id, guards), "text/html; charset=utf-8");
    });

    // -- "Get live info": dispatch REAL plugin instructions at the device NOW and
    // poll the response store for the result. NOT the 30s heartbeat, NOT the
    // warehouse — each panel runs an instruction that queries the live OS. The
    // shell embeds one auto-loading panel per kind; each panel hx-gets .../run
    // (which dispatches + returns a polling div) and the div polls .../result.
    //
    // Posture mirrors the DEX device-perf dispatch (dex_routes.cpp): auth, then
    // an Execute PROBE against a throwaway response (htmx swallows a raw 403, so
    // a read-only operator gets an honest in-panel note instead), then dispatch
    // through the shared chokepoint, audited per-kind.
    auto note = [](httplib::Response& res, const std::string& text) {
        res.set_content("<div class=\"gp-note\">" + text + "</div>", "text/html; charset=utf-8");
    };
    auto can_execute = [this](const httplib::Request& req, const std::string& id) {
        httplib::Response probe; // throwaway: htmx swallows a raw 403, so probe -> note
        return scoped_perm_fn_ && scoped_perm_fn_(req, probe, "Execution", "Execute", id);
    };
    auto url_enc = [](const std::string& s) {
        static const char* kHex = "0123456789ABCDEF";
        std::string out;
        for (unsigned char c : s) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                out += static_cast<char>(c);
            else { out += '%'; out += kHex[c >> 4]; out += kHex[c & 0x0F]; }
        }
        return out;
    };
    // `kind` is already validated against the allowlist before this is called.
    // `command_id2` carries the optional secondary dispatch (process_tree's
    // connections); empty when the kind has no join.
    auto live_pending = [url_enc](const std::string& command_id, const std::string& command_id2,
                                  const std::string& agent_id, const std::string& kind, int attempt) {
        std::string u = "/fragments/device/live/result?command_id=" + url_enc(command_id) +
                        "&amp;agent_id=" + url_enc(agent_id) + "&amp;kind=" + url_enc(kind) +
                        "&amp;n=" + std::to_string(attempt);
        if (!command_id2.empty())
            u += "&amp;command_id2=" + url_enc(command_id2);
        return "<div hx-get=\"" + u +
               "\" hx-trigger=\"load delay:700ms\" hx-swap=\"outerHTML\" class=\"gp-note\">"
               "Waiting for the device to respond&hellip;</div>";
    };

    // Shell: a header + one auto-loading panel per live instruction. Probe Execute once
    // here (LOW, review #1585): a read-only operator (Read but not Execute) would
    // otherwise get the full nine-card interactive shell — each card then degrading to a
    // permission note on /run — which reveals the behavioral categories the product can
    // enumerate. Render a single placeholder instead when Execute is absent.
    sink.Get("/fragments/device/live", [this, note, can_execute](const httplib::Request& req,
                                                                 httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // Per-device live surface: scoped Read floor (the run panels re-gate Read +
        // Execute per dispatch). 403 = outside the caller's management scope.
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        if (!can_execute(req, id)) {
            note(res, "Live device info needs the <b>Execute</b> permission &mdash; it runs "
                      "read-only instructions on the device.");
            return;
        }
        res.set_content(render_device_live_shell(id), "text/html; charset=utf-8");
    });

    // Run: validate kind (allowlist) -> Execute probe -> dispatch -> audit -> poll.
    sink.Get("/fragments/device/live/run", [this, note, can_execute, live_pending](
                                               const httplib::Request& req,
                                               httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        const std::string kind = req.has_param("kind") ? req.get_param_value("kind") : "";
        // Per-device scoped Read floor (tier + management group for THIS device);
        // the Execute probe below is the soft, htmx-friendly note for a read-only
        // operator. Gate before any dispatch so an out-of-scope agent_id is refused.
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        const auto lk = resolve_live_kind(kind);
        if (!lk || id.empty()) { res.status = 400; res.set_content("bad request", "text/plain"); return; }
        if (!can_execute(req, id)) {
            note(res, "Live device info needs the <b>Execute</b> permission &mdash; it runs a "
                      "read-only instruction on the device.");
            return;
        }
        if (!dispatch_fn_ || !responses_fn_) {
            note(res, "Live device query unavailable on this server.");
            return;
        }
        const auto [command_id, sent] =
            dispatch_fn_(lk->plugin, lk->action, {id}, "", {});
        // Optional SECONDARY dispatch joined at render (process_tree -> connections).
        // Dispatched to the SAME device; the result route polls it best-effort.
        std::string command_id2;
        if (!lk->plugin2.empty() && sent > 0) {
            const auto [cid2, sent2] = dispatch_fn_(lk->plugin2, lk->action2, {id}, "", {});
            if (sent2 > 0)
                command_id2 = cid2;
        }
        // Audit the DISPATCH (post-dispatch "dispatched"/"no_agents"). HIGH-1 (review
        // #1585): AuditFn is bool-returning — capture it and surface Sec-Audit-Failed so
        // an audit-store outage is visible to a SIEM instead of silently swallowed (the
        // dashboard fragment still renders; the REST sibling fails closed). NOTE (#1549):
        // the REST sibling audits "requested" PRE-dispatch; aligning this dashboard path
        // to pre-dispatch is a tracked follow-up — until then a result= query for
        // device.live.* must match BOTH "dispatched" and "requested".
        if (audit_fn_ &&
            !audit_fn_(req, lk->audit_action, sent > 0 ? "dispatched" : "no_agents", "Agent", id,
                       lk->plugin + "/" + lk->action +
                           (lk->plugin2.empty() ? "" : " + " + lk->plugin2 + "/" + lk->action2) +
                           " -> " + std::to_string(sent) + " agent(s) command_id=" + command_id))
            res.set_header("Sec-Audit-Failed", "true");
        if (sent == 0) {
            note(res, "Device offline &mdash; live info needs a connected agent.");
            return;
        }
        res.set_content(live_pending(command_id, command_id2, id, kind, 1),
                        "text/html; charset=utf-8");
    });

    // Result: re-validate kind + Execute + command_id prefix + agent match, then
    // poll the response store and render (data rides RUNNING rows, the
    // response-store contract DexRoutes relies on).
    sink.Get("/fragments/device/live/result", [this, note, can_execute, live_pending](
                                                  const httplib::Request& req,
                                                  httplib::Response& res) {
        const std::string kind = req.has_param("kind") ? req.get_param_value("kind") : "";
        const std::string command_id =
            req.has_param("command_id") ? req.get_param_value("command_id") : "";
        const std::string id = req.has_param("agent_id") ? req.get_param_value("agent_id") : "";
        const std::string command_id2 =
            req.has_param("command_id2") ? req.get_param_value("command_id2") : "";
        // Per-device scoped Read floor — a poll must honour the same management
        // scope as the dispatch (an out-of-scope agent_id is refused even with a
        // guessed command_id).
        if (!scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)) return;
        const auto lk = resolve_live_kind(kind);
        if (!lk) { res.status = 400; res.set_content("bad request", "text/plain"); return; }
        // Only THIS kind's plugin commands are pollable here, only for the named
        // agent — narrows what a guessed/stolen command_id can read via this route.
        // The optional secondary id must match the kind's secondary plugin prefix.
        if (id.empty() || command_id.size() > 64 || !command_id.starts_with(lk->plugin + "-")) {
            res.status = 400; res.set_content("bad request", "text/plain"); return;
        }
        if (!command_id2.empty() &&
            (lk->plugin2.empty() || command_id2.size() > 64 ||
             !command_id2.starts_with(lk->plugin2 + "-"))) {
            res.status = 400; res.set_content("bad request", "text/plain"); return;
        }
        if (!can_execute(req, id)) {
            note(res, "Live device info needs the <b>Execute</b> permission.");
            return;
        }
        if (!responses_fn_) {
            note(res, "Live device query unavailable on this server.");
            return;
        }
        // Poll budget: hashing every running binary (processes/list_tree) can
        // take longer than a warehouse query, so allow more attempts before
        // declaring a timeout (~28s at 700ms cadence).
        constexpr int kMaxAttempts = 40;
        int attempt = 1;
        if (req.has_param("n")) {
            try { attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 50); } catch (...) {}
        }
        // Hoist the responses into a named local: pointers below must outlive the loop,
        // so iterating the temporary directly would dangle (use-after-free). #1634: the
        // read is scoped to `id` AT THE STORE SEAM (responses_fn_ passes
        // ResponseQuery{.agent_id}); the post-filter below is defense-in-depth.
        const auto rows = responses_fn_(command_id, id);
        const DexAgentResponse* with_output = nullptr;
        const DexAgentResponse* terminal = nullptr; // SUCCESS or any failure terminal
        for (const auto& r : rows) {
            if (r.agent_id != id) continue; // another agent's rows are never rendered here
            if (!r.output.empty()) with_output = &r;
            if (r.status >= 1) terminal = &r; // 1=SUCCESS, 2+=FAILURE/TIMEOUT/REJECTED
        }
        // Best-effort secondary output (process_tree's connections); whatever is
        // available when the primary renders is joined — the tree renders with or
        // without it (own local outlives the loop below, like `rows`).
        std::string output2;
        std::vector<DexAgentResponse> rows2;
        if (!command_id2.empty()) {
            rows2 = responses_fn_(command_id2, id);
            for (const auto& r : rows2)
                if (r.agent_id == id && !r.output.empty() && !r.output.starts_with("error|"))
                    output2 = r.output;
        }
        if (with_output) {
            if (with_output->output.starts_with("error|")) {
                note(res, "The device reported an error: " +
                              html_escape(with_output->output.substr(6, 200)));
                return;
            }
            res.set_content(render_live_result(kind, *lk, with_output->output, output2),
                            "text/html; charset=utf-8");
            return;
        }
        if (terminal) {
            // The command COMPLETED. Failure → honest note; success-with-no-output
            // → render the empty result now (don't poll to a false timeout — UP-1).
            if (terminal->status >= 2) {
                note(res, "Query failed on the device: " +
                              html_escape(terminal->error_detail.substr(0, 200)));
                return;
            }
            res.set_content(render_live_result(kind, *lk, "", output2), "text/html; charset=utf-8");
            return;
        }
        if (attempt >= kMaxAttempts) {
            note(res, "No response from the device (timed out) &mdash; it may have gone offline. "
                      "Reload to retry.");
            return;
        }
        res.set_content(live_pending(command_id, command_id2, id, kind, attempt + 1),
                        "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
