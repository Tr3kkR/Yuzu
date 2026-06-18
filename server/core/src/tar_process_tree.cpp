/// @file tar_process_tree.cpp
/// Implementation of the TAR process-tree reconstruction engine + pure renderers.
/// See tar_process_tree.hpp for the data-source constraints that shape this model.

#include "tar_process_tree.hpp"

#include "web_utils.hpp" // html_escape, format_iso_utc, format_relative_time

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <format>
#include <optional>
#include <string_view>

namespace yuzu::server {

namespace {

std::vector<std::string> split_pipe(const std::string& line) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (true) {
        const auto bar = line.find('|', pos);
        if (bar == std::string::npos) {
            out.push_back(line.substr(pos));
            return out;
        }
        out.push_back(line.substr(pos, bar - pos));
        pos = bar + 1;
    }
}

std::string to_lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

/// Image basename, lowercased — strips any directory prefix (`/` or `\`) so a
/// Linux cmdline path and a Windows image name compare on the same key.
std::string basename_lower(const std::string& name) {
    auto slash = name.find_last_of("/\\");
    std::string base = (slash == std::string::npos) ? name : name.substr(slash + 1);
    return to_lower(base);
}

/// Parse an agent-supplied cell to a bounded non-negative integer. nullopt on any
/// garbage / overflow / trailing junk (the whole row is then skipped). Bounded to
/// 2^63 via int64 so pid/port/ts all share one safe path.
std::optional<std::int64_t> cell_i64(const std::string& s) {
    if (s.empty() || s.size() > 20)
        return std::nullopt;
    std::int64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9')
            return std::nullopt;
        // Overflow guard (v*10+d) — reject rather than wrap.
        if (v > (INT64_MAX - 9) / 10)
            return std::nullopt;
        v = v * 10 + (c - '0');
    }
    return v;
}

/// Schema-located column map: index by NAME from the `__schema__|col1|…` header
/// (schema cell i names data cell i-1). Returns the data-cell index for `name`, or
/// -1 if absent. Mirrors parse_dex_perf_output's defensive contract.
int schema_index(const std::vector<std::string>& schema_cells, std::string_view name) {
    for (int i = 1; i < static_cast<int>(schema_cells.size()); ++i)
        if (schema_cells[i] == name)
            return i - 1;
    return -1;
}

// ── Suspicious parent→child denylist (the sole anomaly heuristic) ────────────
// High-signal LOLBin / shell spawns. explorer.exe is DELIBERATELY excluded as a
// parent: a user opening a terminal from Explorer is benign and would swamp the
// signal. Name-based so it works on Windows (ETW names-only). Basenames, lowercase.
const std::array<std::string_view, 17> kSuspiciousParents = {
    "winword.exe", "excel.exe",   "powerpnt.exe", "outlook.exe", "onenote.exe",
    "msaccess.exe", "mspub.exe",  "visio.exe",    "chrome.exe",  "msedge.exe",
    "firefox.exe",  "iexplore.exe", "acrord32.exe", "mshta.exe",  "wmiprvse.exe",
    "wscript.exe",  "cscript.exe"};
const std::array<std::string_view, 14> kSuspiciousChildren = {
    "powershell.exe", "pwsh.exe",    "cmd.exe",     "wscript.exe", "cscript.exe",
    "mshta.exe",      "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "certutil.exe",
    "bash", "sh", "bash.exe", "sh.exe"};

} // namespace

bool tar_is_suspicious_spawn(const std::string& parent_name, const std::string& child_name,
                             std::string* evidence) {
    const std::string p = basename_lower(parent_name);
    const std::string c = basename_lower(child_name);
    if (p.empty() || c.empty())
        return false;
    const bool parent_hit =
        std::find(kSuspiciousParents.begin(), kSuspiciousParents.end(), p) != kSuspiciousParents.end();
    const bool child_hit =
        std::find(kSuspiciousChildren.begin(), kSuspiciousChildren.end(), c) != kSuspiciousChildren.end();
    if (!parent_hit || !child_hit)
        return false;
    if (evidence)
        *evidence = parent_name + " \xE2\x86\x92 " + child_name +
                    " \xE2\x80\x94 uncommon parent spawned a shell/LOLBin";
    return true;
}

std::vector<TarProcEvent> parse_tar_process_output(const std::string& output, std::size_t max_rows) {
    std::vector<TarProcEvent> out;
    int c_ts = -1, c_action = -1, c_pid = -1, c_ppid = -1, c_name = -1, c_cmd = -1, c_user = -1;
    bool have_schema = false;
    std::size_t pos = 0;
    while (pos < output.size() && out.size() < max_rows) {
        const auto nl = output.find('\n', pos);
        std::string line = output.substr(pos, (nl == std::string::npos ? output.size() : nl) - pos);
        pos = (nl == std::string::npos) ? output.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        if (!have_schema) {
            if (line.starts_with("error|"))
                return out; // agent-side error payload
            if (!line.starts_with("__schema__|"))
                continue;
            const auto cols = split_pipe(line);
            c_ts = schema_index(cols, "ts");
            c_action = schema_index(cols, "action");
            c_pid = schema_index(cols, "pid");
            c_ppid = schema_index(cols, "ppid");
            c_name = schema_index(cols, "name");
            c_cmd = schema_index(cols, "cmdline");
            c_user = schema_index(cols, "user");
            // ppid/name/user may legitimately be empty cells, but the COLUMNS must
            // exist; cmdline is optional (Windows omits content, not the column).
            if (c_ts < 0 || c_action < 0 || c_pid < 0 || c_ppid < 0 || c_name < 0)
                return out; // wrong shape — refuse rather than guess
            have_schema = true;
            continue;
        }
        const auto cells = split_pipe(line);
        const int need = (std::max)({c_ts, c_action, c_pid, c_ppid, c_name,
                                     c_cmd < 0 ? 0 : c_cmd, c_user < 0 ? 0 : c_user});
        if (static_cast<int>(cells.size()) <= need)
            continue; // trailer ("total|N") or torn row
        const auto ts = cell_i64(cells[static_cast<std::size_t>(c_ts)]);
        const auto pid = cell_i64(cells[static_cast<std::size_t>(c_pid)]);
        const auto ppid = cell_i64(cells[static_cast<std::size_t>(c_ppid)]);
        if (!ts || !pid || !ppid || *pid > UINT32_MAX || *ppid > UINT32_MAX)
            continue;
        TarProcEvent e;
        e.ts = *ts;
        e.action = to_lower(cells[static_cast<std::size_t>(c_action)]);
        e.pid = static_cast<std::uint32_t>(*pid);
        e.ppid = static_cast<std::uint32_t>(*ppid);
        e.name = cells[static_cast<std::size_t>(c_name)];
        if (c_cmd >= 0)
            e.cmdline = cells[static_cast<std::size_t>(c_cmd)];
        if (c_user >= 0)
            e.user = cells[static_cast<std::size_t>(c_user)];
        out.push_back(std::move(e));
    }
    return out;
}

std::vector<TarTcpConn> parse_tar_tcp_output(const std::string& output, std::size_t max_rows) {
    std::vector<TarTcpConn> out;
    int c_pid = -1, c_pname = -1, c_proto = -1, c_lport = -1, c_raddr = -1, c_rport = -1,
        c_state = -1, c_ts = -1, c_action = -1;
    bool have_schema = false;
    std::size_t pos = 0;
    while (pos < output.size() && out.size() < max_rows) {
        const auto nl = output.find('\n', pos);
        std::string line = output.substr(pos, (nl == std::string::npos ? output.size() : nl) - pos);
        pos = (nl == std::string::npos) ? output.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        if (!have_schema) {
            if (line.starts_with("error|"))
                return out;
            if (!line.starts_with("__schema__|"))
                continue;
            const auto cols = split_pipe(line);
            c_pid = schema_index(cols, "pid");
            c_pname = schema_index(cols, "process_name");
            c_proto = schema_index(cols, "proto");
            c_lport = schema_index(cols, "local_port");
            c_raddr = schema_index(cols, "remote_addr");
            c_rport = schema_index(cols, "remote_port");
            c_state = schema_index(cols, "state");
            c_ts = schema_index(cols, "ts");
            c_action = schema_index(cols, "action");
            if (c_pid < 0 || c_raddr < 0)
                return out; // need at least the join key + remote
            have_schema = true;
            continue;
        }
        const auto cells = split_pipe(line);
        auto at = [&](int idx) -> std::string {
            return (idx >= 0 && idx < static_cast<int>(cells.size()))
                       ? cells[static_cast<std::size_t>(idx)]
                       : std::string{};
        };
        const auto pid = cell_i64(at(c_pid));
        if (!pid || *pid > UINT32_MAX)
            continue;
        TarTcpConn t;
        t.pid = static_cast<std::uint32_t>(*pid);
        t.process_name = at(c_pname);
        t.proto = at(c_proto);
        if (auto v = cell_i64(at(c_lport)); v && *v <= 65535)
            t.local_port = static_cast<int>(*v);
        t.remote_addr = at(c_raddr);
        if (auto v = cell_i64(at(c_rport)); v && *v <= 65535)
            t.remote_port = static_cast<int>(*v);
        t.state = at(c_state);
        if (auto v = cell_i64(at(c_ts)); v)
            t.ts = *v;
        t.action = to_lower(at(c_action));
        out.push_back(std::move(t));
    }
    return out;
}

TarTreeAnchors compute_tar_anchors(const std::vector<TarProcEvent>& events) {
    TarTreeAnchors a;
    bool first = true;
    std::int64_t boot = 0;
    for (const auto& e : events) {
        if (first || e.ts < a.observed_since) {
            a.observed_since = e.ts;
            first = false;
        }
        // Best-effort boot signal: the most-recent START of a canonical root process
        // (ppid==0 — Windows "System" pid 4 / Linux init pid 1). TAR has no boot-time
        // column; this is the closest in-band proxy and falls back to install below.
        const bool start = (e.action == "started" || e.action == "start");
        if (start && e.ppid == 0 && e.ts > boot)
            boot = e.ts;
    }
    a.install_ts = a.observed_since;
    a.boot_ts = boot > 0 ? boot : a.observed_since;
    return a;
}

TarWindow resolve_tar_window(const std::string& preset, std::int64_t custom_from,
                             std::int64_t custom_to, const TarTreeAnchors& anchors,
                             std::int64_t now) {
    TarWindow w;
    w.to_ts = now;
    if (preset == "on_boot") {
        w.from_ts = anchors.boot_ts;
    } else if (preset == "on_install") {
        w.from_ts = anchors.install_ts;
    } else if (preset == "1m") {
        w.from_ts = now - 60;
    } else if (preset == "1h") {
        w.from_ts = now - 3600;
    } else if (preset == "1d") {
        w.from_ts = now - 86400;
    } else if (preset == "custom") {
        w.from_ts = custom_from > 0 ? custom_from : anchors.install_ts;
        w.to_ts = custom_to > 0 ? custom_to : now;
    } else {
        // default / "10m"
        w.from_ts = now - 600;
    }
    if (w.from_ts < 0)
        w.from_ts = 0;
    if (w.to_ts < w.from_ts)
        w.to_ts = w.from_ts; // reversed range → point-in-time at `to`
    return w;
}

namespace {

/// A pid's lifetime as walked from the event stream (one incarnation).
struct Incarnation {
    std::uint32_t pid = 0;
    std::uint32_t ppid = 0;
    std::string name;
    std::string cmdline;
    std::string user;
    std::int64_t start = 0;
    std::int64_t end = 0; // 0 = still running at `to`
    bool start_known = false;
    bool running = false;
};

bool is_start(const std::string& action) {
    return action == "started" || action == "start";
}
bool is_stop(const std::string& action) {
    return action == "stopped" || action == "stop";
}

} // namespace

TarProcTree reconstruct_tar_process_tree(const std::vector<TarProcEvent>& events_in,
                                         std::int64_t from_ts, std::int64_t to_ts,
                                         const TarTreeAnchors& anchors) {
    TarProcTree tree;
    tree.from_ts = from_ts;
    tree.to_ts = to_ts;
    tree.anchors = anchors;

    // 1. Bucket events by pid, only those at or before `to` (defensive even though
    //    the route fetches ts<=to), sorted by (ts, starts-before-stops).
    std::unordered_map<std::uint32_t, std::vector<const TarProcEvent*>> by_pid;
    for (const auto& e : events_in)
        if (e.ts <= to_ts)
            by_pid[e.pid].push_back(&e);

    std::vector<Incarnation> incs;
    for (auto& [pid, evs] : by_pid) {
        std::stable_sort(evs.begin(), evs.end(), [](const TarProcEvent* a, const TarProcEvent* b) {
            if (a->ts != b->ts)
                return a->ts < b->ts;
            return is_start(a->action) && !is_start(b->action); // starts before stops at a tie
        });
        std::optional<Incarnation> cur;
        for (const TarProcEvent* e : evs) {
            if (is_start(e->action)) {
                if (cur) {
                    // A start while still "open" means the pid was reused — the prior
                    // incarnation must have ended; close it at this ts.
                    cur->end = e->ts;
                    incs.push_back(std::move(*cur));
                }
                Incarnation inc;
                inc.pid = pid;
                inc.ppid = e->ppid;
                inc.name = e->name;
                inc.cmdline = e->cmdline;
                inc.user = e->user;
                inc.start = e->ts;
                inc.start_known = true;
                cur = std::move(inc);
            } else if (is_stop(e->action)) {
                if (cur) {
                    cur->end = e->ts;
                    incs.push_back(std::move(*cur));
                    cur.reset();
                } else {
                    // A stop with no surviving start — its `started` aged out of the
                    // live cap (no seed). Synthesise a "started before observation"
                    // incarnation from the stop row's fields (which carry name/ppid).
                    Incarnation inc;
                    inc.pid = pid;
                    inc.ppid = e->ppid;
                    inc.name = e->name;
                    inc.cmdline = e->cmdline;
                    inc.user = e->user;
                    inc.start = 0;
                    inc.start_known = false;
                    inc.end = e->ts;
                    incs.push_back(std::move(inc));
                }
            }
        }
        if (cur) { // open at end of stream → running at `to`
            cur->running = true;
            cur->end = 0;
            incs.push_back(std::move(*cur));
        }
    }

    // 2. Window-overlap filter: keep an incarnation if it was alive at any point in
    //    [from, to] — running (alive at `to`) OR it exited at/after `from`.
    std::vector<Incarnation> kept;
    kept.reserve(incs.size());
    for (auto& inc : incs) {
        if (inc.running || inc.end >= from_ts)
            kept.push_back(std::move(inc));
    }
    // 3. Node cap: keep the most-recent kTarTreeMaxNodes (largest start) on overflow.
    if (kept.size() > kTarTreeMaxNodes) {
        std::partial_sort(kept.begin(), kept.begin() + kTarTreeMaxNodes, kept.end(),
                          [](const Incarnation& a, const Incarnation& b) { return a.start > b.start; });
        kept.resize(kTarTreeMaxNodes);
        tree.truncated = true;
    }

    // Materialise nodes (stable node_id = index).
    tree.nodes.reserve(kept.size());
    for (const auto& inc : kept) {
        TarProcNode n;
        n.pid = inc.pid;
        n.ppid = inc.ppid;
        n.name = inc.name;
        n.cmdline = inc.cmdline;
        n.user = inc.user;
        n.started_ts = inc.start;
        n.start_known = inc.start_known;
        n.exited_ts = inc.running ? 0 : inc.end;
        n.running = inc.running;
        tree.nodes.push_back(std::move(n));
    }

    // 4. Parent resolution: a child links to the incarnation of its ppid whose
    //    lifetime contained the child's start. pid index for the lookup.
    std::unordered_map<std::uint32_t, std::vector<std::size_t>> pid_to_nodes;
    for (std::size_t i = 0; i < tree.nodes.size(); ++i)
        pid_to_nodes[tree.nodes[i].pid].push_back(i);

    auto node_lo = [&](std::size_t id) -> std::int64_t {
        return tree.nodes[id].start_known ? tree.nodes[id].started_ts : from_ts;
    };
    auto node_hi = [&](std::size_t id) -> std::int64_t {
        return tree.nodes[id].running ? to_ts : tree.nodes[id].exited_ts;
    };
    constexpr std::size_t kMaxDepthGuard = 4096;
    for (std::size_t i = 0; i < tree.nodes.size(); ++i) {
        TarProcNode& n = tree.nodes[i];
        if (n.ppid == 0 || n.ppid == n.pid)
            continue; // root
        auto it = pid_to_nodes.find(n.ppid);
        if (it == pid_to_nodes.end())
            continue; // parent not present → orphan/reparented root
        const std::int64_t child_start = node_lo(i);
        std::size_t best = TarProcNode::kNoParent;
        std::int64_t best_lo = INT64_MIN;
        for (std::size_t pcand : it->second) {
            if (pcand == i)
                continue;
            const std::int64_t plo = node_lo(pcand), phi = node_hi(pcand);
            const bool contains = plo <= child_start && child_start <= phi;
            // Prefer the incarnation whose interval contains the child's start; among
            // those, the most-recent (largest plo). If none contains, fall back to the
            // most-recent incarnation that started before the child.
            if (contains && plo >= best_lo) {
                best = pcand;
                best_lo = plo;
            } else if (best == TarProcNode::kNoParent && plo <= child_start && plo >= best_lo) {
                best = pcand;
                best_lo = plo;
            }
        }
        if (best == TarProcNode::kNoParent)
            continue; // root
        // Cycle guard: walking up from `best` must not reach `i` (pid reuse can form
        // a loop). If it would, leave `i` a root instead of closing the cycle.
        std::size_t walk = best;
        std::size_t depth = 0;
        bool cycle = false;
        while (walk != TarProcNode::kNoParent && depth++ < kMaxDepthGuard) {
            if (walk == i) {
                cycle = true;
                break;
            }
            walk = tree.nodes[walk].parent;
        }
        if (cycle)
            continue; // keep `i` as a root
        n.parent = best;
    }

    // 5. Children lists + root set from the final parent fields.
    for (std::size_t i = 0; i < tree.nodes.size(); ++i) {
        if (tree.nodes[i].parent == TarProcNode::kNoParent)
            tree.roots.push_back(i);
        else
            tree.nodes[tree.nodes[i].parent].children.push_back(i);
    }
    // Stable sibling order: by pid then start.
    auto sib_less = [&](std::size_t a, std::size_t b) {
        if (tree.nodes[a].pid != tree.nodes[b].pid)
            return tree.nodes[a].pid < tree.nodes[b].pid;
        return tree.nodes[a].started_ts < tree.nodes[b].started_ts;
    };
    std::sort(tree.roots.begin(), tree.roots.end(), sib_less);
    for (auto& n : tree.nodes)
        std::sort(n.children.begin(), n.children.end(), sib_less);

    // 6. Anomaly flag: suspicious parent→child name pairs.
    for (auto& n : tree.nodes) {
        if (n.parent == TarProcNode::kNoParent)
            continue;
        std::string ev;
        if (tar_is_suspicious_spawn(tree.nodes[n.parent].name, n.name, &ev)) {
            n.anomaly = true;
            n.anomaly_evidence = std::move(ev);
        }
    }

    // 7. Counts over the full tree (reachable from roots) — for the banner. Running/
    //    exited/anomalies-only filtering is applied client-side at display time, so
    //    the reconstruction itself is never pruned (every node stays addressable by
    //    the detail route, and a filter toggle needs no re-dispatch).
    std::vector<bool> seen(tree.nodes.size(), false);
    std::vector<std::size_t> stack = tree.roots;
    while (!stack.empty()) {
        std::size_t id = stack.back();
        stack.pop_back();
        if (id >= tree.nodes.size() || seen[id])
            continue;
        seen[id] = true;
        const TarProcNode& n = tree.nodes[id];
        if (n.running)
            ++tree.running_count;
        else
            ++tree.exited_count;
        if (n.anomaly)
            ++tree.anomaly_count;
        for (std::size_t c : n.children)
            stack.push_back(c);
    }
    return tree;
}

// ── Renderers ────────────────────────────────────────────────────────────────

namespace {

bool os_is_windows(const std::string& os) {
    const std::string o = to_lower(os);
    return o.find("win") != std::string::npos;
}

/// Coarse class of a remote address for inline colouring: "loop" (loopback),
/// "priv" (RFC1918 / ULA / link-local), "pub" (routable), or "" (empty/unknown).
/// Forensic value: a public remote is the egress an analyst cares about.
std::string remote_class(const std::string& addr) {
    if (addr.empty() || addr == "0.0.0.0" || addr == "::" || addr == "*")
        return "";
    if (addr.starts_with("127.") || addr == "::1")
        return "loop";
    if (addr.starts_with("10.") || addr.starts_with("192.168.") || addr.starts_with("169.254.") ||
        addr.starts_with("fe80:") || addr.starts_with("fc") || addr.starts_with("fd"))
        return "priv";
    if (addr.starts_with("172.")) {
        // 172.16.0.0 – 172.31.255.255 is private; other 172.x is public.
        int second = 0;
        std::size_t dot = addr.find('.', 4);
        if (dot != std::string::npos) {
            try {
                second = std::stoi(addr.substr(4, dot - 4));
            } catch (...) {
            }
        }
        return (second >= 16 && second <= 31) ? "priv" : "pub";
    }
    return "pub";
}

/// One distinct remote endpoint label (`addr:port`, or `:port listen` for a
/// listener), HTML-escaped, wrapped in a class that colours public egress.
std::string endpoint_chip(const TarTcpConn& c) {
    const std::string cls = remote_class(c.remote_addr);
    std::string label;
    if (cls.empty() || c.remote_port == 0)
        label = ":" + std::to_string(c.local_port) + " listen";
    else
        label = c.remote_addr + ":" + std::to_string(c.remote_port);
    std::string klass = "tt-ep";
    if (cls == "pub")
        klass += " tt-ep-pub";
    return "<span class=\"" + klass + "\">" + html_escape(label) + "</span>";
}

/// Inline network summary for a node's connections (already filtered to its pid):
/// a count badge + up to two distinct endpoints + "+N", with the full list in the
/// title. Empty string when the node has no connections.
std::string net_cell(const std::vector<const TarTcpConn*>& conns) {
    if (conns.empty())
        return {};
    // Distinct endpoints, public first, preserving first-seen order otherwise.
    std::vector<const TarTcpConn*> distinct;
    std::vector<std::string> seen;
    bool any_public = false;
    for (const TarTcpConn* c : conns) {
        std::string key = c->remote_addr + ":" + std::to_string(c->remote_port) + "/" +
                          std::to_string(c->local_port);
        if (std::find(seen.begin(), seen.end(), key) != seen.end())
            continue;
        seen.push_back(key);
        distinct.push_back(c);
        if (remote_class(c->remote_addr) == "pub")
            any_public = true;
    }
    std::stable_sort(distinct.begin(), distinct.end(), [](const TarTcpConn* a, const TarTcpConn* b) {
        return (remote_class(a->remote_addr) == "pub") && (remote_class(b->remote_addr) != "pub");
    });
    std::string title;
    for (std::size_t i = 0; i < distinct.size() && i < 12; ++i) {
        const TarTcpConn* c = distinct[i];
        title += (c->remote_addr.empty() ? ":" + std::to_string(c->local_port)
                                         : c->remote_addr + ":" + std::to_string(c->remote_port));
        if (!c->proto.empty())
            title += " " + c->proto;
        title += "  ";
    }
    std::string cell = "<span class=\"tt-net" + std::string(any_public ? " tt-net-pub" : "") +
                       "\" title=\"" + html_escape(title) + "\">";
    cell += "<span class=\"tt-net-ico\">\xE2\x86\x97</span>" + std::to_string(distinct.size());
    for (std::size_t i = 0; i < distinct.size() && i < 2; ++i)
        cell += endpoint_chip(*distinct[i]);
    if (distinct.size() > 2)
        cell += "<span class=\"tt-ep tt-ep-more\">+" + std::to_string(distinct.size() - 2) + "</span>";
    cell += "</span>";
    return cell;
}

using ConnIndex = std::unordered_map<std::uint32_t, std::vector<const TarTcpConn*>>;

/// One node's summary row (the clickable line). `node_id` addresses the detail; the
/// row carries data-state/data-anom for the client-side filters.
std::string node_summary_row(const TarProcTree& tree, std::size_t id, const std::string& token,
                             const ConnIndex& conn_index) {
    const TarProcNode& n = tree.nodes[id];
    const char* state = n.running ? "running" : "exited";
    std::string row;
    row += "<a class=\"tar-tree-row\" data-state=\"";
    row += state;
    row += "\" data-anom=\"";
    row += n.anomaly ? "1" : "0";
    row += "\" hx-get=\"/fragments/tar/process-tree/detail?token=" + token +
           "&amp;node=" + std::to_string(id) +
           "\" hx-target=\"#tar-tree-detail\" hx-swap=\"innerHTML\">";
    row += n.running ? "<span class=\"tt-dot tt-dot-run\"></span>"
                     : "<span class=\"tt-dot tt-dot-exit\"></span>";
    row += "<span class=\"tt-pid\">" + std::to_string(n.pid) + "</span>";
    row += "<span class=\"tt-name\">" + html_escape(n.name.empty() ? "(unknown)" : n.name) + "</span>";
    if (!n.user.empty())
        row += "<span class=\"tt-user\">" + html_escape(n.user) + "</span>";
    if (!n.running)
        row += "<span class=\"tt-meta\" title=\"" + html_escape(format_iso_utc(n.exited_ts)) +
               "\">exited " + html_escape(format_relative_time(n.exited_ts, tree.to_ts)) + "</span>";
    auto it = conn_index.find(n.pid);
    if (it != conn_index.end())
        row += net_cell(it->second);
    if (n.anomaly)
        row += "<span class=\"tt-anom\" title=\"" + html_escape(n.anomaly_evidence) +
               "\">\xE2\x9A\xA0</span>";
    row += "</a>";
    return row;
}

// Group same-name siblings into one collapsible row once there are at least this
// many (cleans up e.g. dozens of svchost.exe under services.exe).
constexpr std::size_t kTarGroupThreshold = 4;

void render_node(const TarProcTree& tree, std::size_t id, int depth, const std::string& token,
                 const ConnIndex& conn_index, std::string& out); // fwd (mutual recursion)

/// One collapsed "name ×N" group summarising same-name siblings; expands to the
/// individual PIDs (each still drill-able). Collapsed by default — the cleanup.
void render_group(const TarProcTree& tree, const std::string& name,
                  const std::vector<std::size_t>& group, int depth, const std::string& token,
                  const ConnIndex& conn_index, std::string& out) {
    int run = 0, ex = 0, anom = 0;
    for (std::size_t id : group) {
        tree.nodes[id].running ? ++run : ++ex;
        if (tree.nodes[id].anomaly)
            ++anom;
    }
    out += "<details class=\"tar-tree-node tar-tree-group\"><summary><span class=\"tar-tree-row "
           "tt-group\">";
    out += "<span class=\"tt-group-ico\">\xE2\x96\xA6</span>";
    out += "<span class=\"tt-name\">" + html_escape(name.empty() ? "(unknown)" : name) + "</span>";
    out += "<span class=\"tt-group-count\">\xC3\x97" + std::to_string(group.size()) + "</span>";
    out += "<span class=\"tt-meta\">" + std::to_string(run) + " running";
    if (ex > 0)
        out += " \xC2\xB7 " + std::to_string(ex) + " exited";
    out += "</span>";
    if (anom > 0)
        out += "<span class=\"tt-anom\">\xE2\x9A\xA0 " + std::to_string(anom) + "</span>";
    out += "</span></summary><div class=\"tar-tree-children\">";
    for (std::size_t id : group)
        render_node(tree, id, depth + 1, token, conn_index, out);
    out += "</div></details>";
}

/// Render a sibling set, grouping same-name runs of >= kTarGroupThreshold into a
/// single collapsed group (first-appearance order).
void render_children(const TarProcTree& tree, const std::vector<std::size_t>& ids, int depth,
                     const std::string& token, const ConnIndex& conn_index, std::string& out) {
    std::vector<bool> done(ids.size(), false);
    for (std::size_t i = 0; i < ids.size(); ++i) {
        if (done[i])
            continue;
        const std::string& nm = tree.nodes[ids[i]].name;
        std::vector<std::size_t> group;
        for (std::size_t j = i; j < ids.size(); ++j) {
            if (!done[j] && tree.nodes[ids[j]].name == nm) {
                group.push_back(ids[j]);
                done[j] = true;
            }
        }
        if (group.size() >= kTarGroupThreshold)
            render_group(tree, nm, group, depth, token, conn_index, out);
        else
            for (std::size_t id : group)
                render_node(tree, id, depth, token, conn_index, out);
    }
}

void render_node(const TarProcTree& tree, std::size_t id, int depth, const std::string& token,
                 const ConnIndex& conn_index, std::string& out) {
    if (id >= tree.nodes.size())
        return;
    if (depth > 256) {
        out += "<div class=\"tar-tree-leaf tar-tree-mute\">\xE2\x80\xA6 (depth capped)</div>";
        return;
    }
    const TarProcNode& n = tree.nodes[id];
    if (n.children.empty()) {
        out += "<div class=\"tar-tree-leaf\">" + node_summary_row(tree, id, token, conn_index) +
               "</div>";
        return;
    }
    // Expand the first two levels by default; deeper branches start collapsed.
    out += depth < 2 ? "<details open class=\"tar-tree-node\">" : "<details class=\"tar-tree-node\">";
    out += "<summary>" + node_summary_row(tree, id, token, conn_index) + "</summary>";
    out += "<div class=\"tar-tree-children\">";
    render_children(tree, n.children, depth + 1, token, conn_index, out);
    out += "</div></details>";
}

} // namespace

std::string render_tar_tree_fragment(const TarProcTree& tree, const std::vector<TarTcpConn>& conns,
                                     const std::string& device_id, const std::string& token,
                                     const std::string& os) {
    (void)device_id;
    // Index connections by owning pid for the inline per-node net summary.
    ConnIndex conn_index;
    for (const auto& c : conns)
        conn_index[c.pid].push_back(&c);

    std::string h;
    // Honesty banner.
    h += "<div class=\"tar-tree-banner\">";
    h += "Window <b>" + html_escape(format_iso_utc(tree.from_ts)) + "</b> \xE2\x86\x92 <b>" +
         html_escape(format_iso_utc(tree.to_ts)) + "</b>";
    h += " &middot; observed since " + html_escape(format_iso_utc(tree.anchors.observed_since));
    h += " &middot; " + std::to_string(tree.running_count + tree.exited_count) + " nodes (" +
         std::to_string(tree.running_count) + " running / " + std::to_string(tree.exited_count) +
         " exited)";
    h += " &middot; " + std::to_string(tree.anomaly_count) + " flagged";
    h += "</div>";
    h += "<div class=\"tar-tree-note\">Reconstructed from this host's local TAR database "
         "(<code>$Process_Live</code>) only \xE2\x80\x94 no seed. Processes whose start event aged "
         "out of the live cap, or that started before the oldest retained row, may not appear. "
         "&ldquo;On boot&rdquo;/&ldquo;On agent install&rdquo; anchors are TAR-derived proxies.";
    if (os_is_windows(os))
        h += " On Windows the process feeder is ETW (names-only): per-process path and command "
             "line are not captured.";
    h += "</div>";

    if (tree.truncated)
        h += "<div class=\"tar-tree-warn\">Tree exceeds the render limit (" +
             std::to_string(kTarTreeMaxNodes) +
             " nodes) \xE2\x80\x94 showing the most recent. Narrow the timescale.</div>";

    if (tree.roots.empty()) {
        h += "<div class=\"tar-tree-empty\">No processes reconstructable for this window. Widen "
             "the timescale, or the host may have no retained process events.</div>";
        return h;
    }

    // Empty-filter hint (shown by the client-side filters when nothing matches).
    h += "<div class=\"tar-tree-nomatch\" style=\"display:none\">No processes match the current "
         "filters.</div>";
    h += "<div class=\"tar-tree\">";
    std::string body;
    render_children(tree, tree.roots, 0, token, conn_index, body);
    h += body;
    h += "</div>";
    return h;
}

std::string render_tar_proc_detail(const TarProcNode& node, const std::vector<TarTcpConn>& conns,
                                   const std::string& os) {
    const bool win = os_is_windows(os);
    std::string h;
    h += "<div class=\"tar-detail\">";
    h += "<div class=\"tar-detail-title\">" +
         html_escape(node.name.empty() ? "(unknown)" : node.name) + " <span class=\"tar-tree-pid\">pid " +
         std::to_string(node.pid) + "</span></div>";

    auto kv = [&](const std::string& k, const std::string& v, bool mono = false) {
        h += "<div class=\"tar-kv\"><span class=\"tar-kv-k\">" + html_escape(k) + "</span>";
        h += mono ? "<code class=\"tar-kv-v\">" : "<span class=\"tar-kv-v\">";
        h += html_escape(v);
        h += mono ? "</code></div>" : "</span></div>";
    };

    kv("PID", std::to_string(node.pid));
    kv("Parent PID", std::to_string(node.ppid));
    if (!node.user.empty())
        kv("User", node.user);
    kv("State", node.running ? "running" : ("exited " + format_iso_utc(node.exited_ts)));
    kv("Started", node.start_known ? format_iso_utc(node.started_ts)
                                    : std::string("before observation (start event not retained)"));

    // Path + command line — TAR-only. Windows ETW is names-only (no path/cmdline).
    if (win) {
        h += "<div class=\"tar-kv\"><span class=\"tar-kv-k\">Path</span>"
             "<span class=\"tar-kv-v tar-tree-mute\">\xE2\x80\x94 names-only on Windows (ETW "
             "feeder)</span></div>";
        h += "<div class=\"tar-kv\"><span class=\"tar-kv-k\">Command line</span>"
             "<span class=\"tar-kv-v tar-tree-mute\">\xE2\x80\x94 names-only on Windows (ETW "
             "feeder)</span></div>";
    } else {
        kv("Path / command line",
           node.cmdline.empty() ? std::string("\xE2\x80\x94 (not captured)") : node.cmdline, true);
    }

    if (node.anomaly) {
        h += "<div class=\"tar-detail-anom\"><span class=\"tar-badge tar-badge-anom\">\xE2\x9A\xA0 "
             "anomaly</span> " +
             html_escape(node.anomaly_evidence) + "</div>";
    }

    // Connections owned by this pid (from $TCP_Live, joined by pid). Most recent first.
    h += "<div class=\"tar-detail-section\">Connections</div>";
    if (conns.empty()) {
        h += "<div class=\"tar-tree-mute\">No TCP connections recorded for this PID in the "
             "window.</div>";
    } else {
        h += "<table class=\"tar-detail-conns\"><thead><tr><th>Proto</th><th>Local</th>"
             "<th>Remote</th><th>State</th><th>When</th></tr></thead><tbody>";
        std::size_t shown = 0;
        for (const auto& c : conns) {
            if (shown++ >= 100)
                break;
            h += "<tr><td>" + html_escape(c.proto) + "</td>";
            h += "<td>:" + std::to_string(c.local_port) + "</td>";
            h += "<td>" + html_escape(c.remote_addr) + ":" + std::to_string(c.remote_port) + "</td>";
            h += "<td>" + html_escape(c.state) + "</td>";
            h += "<td title=\"" + html_escape(format_iso_utc(c.ts)) + "\">" +
                 html_escape(c.action.empty() ? std::string("\xE2\x80\x94") : c.action) + "</td></tr>";
        }
        h += "</tbody></table>";
    }
    h += "</div>";
    return h;
}

} // namespace yuzu::server
