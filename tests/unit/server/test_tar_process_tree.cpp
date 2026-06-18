/// @file test_tar_process_tree.cpp
/// Unit tests for the TAR process-tree reconstruction engine (tar_process_tree.*):
/// the __schema__ parsers, point-in-time/window reconstruction, pid-reuse,
/// orphan→root, the suspicious parent→child anomaly, anomalies-only pruning, the
/// timescale anchors + window resolution, and render HTML-escaping. Pure — no store,
/// no network.

#include "tar_process_tree.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

TarProcEvent ev(std::int64_t ts, const char* action, std::uint32_t pid, std::uint32_t ppid,
                const char* name, const char* user = "", const char* cmd = "") {
    TarProcEvent e;
    e.ts = ts;
    e.action = action;
    e.pid = pid;
    e.ppid = ppid;
    e.name = name;
    e.user = user;
    e.cmdline = cmd;
    return e;
}

// First node with `pid`; nullptr if absent. `running_pref` picks a running
// incarnation when a pid has several.
const TarProcNode* find_pid(const TarProcTree& t, std::uint32_t pid, bool running_pref = false) {
    const TarProcNode* any = nullptr;
    for (const auto& n : t.nodes) {
        if (n.pid != pid)
            continue;
        if (!any)
            any = &n;
        if (running_pref && n.running)
            return &n;
    }
    return any;
}

int count_pid(const TarProcTree& t, std::uint32_t pid) {
    int c = 0;
    for (const auto& n : t.nodes)
        if (n.pid == pid)
            ++c;
    return c;
}

} // namespace

TEST_CASE("tar parse: process __schema__ output", "[tar][tree][parse]") {
    const std::string out =
        "__schema__|ts|action|pid|ppid|name|cmdline|user\n"
        "100|started|1|0|systemd||root\n"
        "110|started|100|1|bash||alice\n"
        "total|2\n"; // trailer row — too few cells, must be skipped
    auto events = parse_tar_process_output(out);
    REQUIRE(events.size() == 2);
    CHECK(events[0].ts == 100);
    CHECK(events[0].pid == 1);
    CHECK(events[0].ppid == 0);
    CHECK(events[0].name == "systemd");
    CHECK(events[0].action == "started");
    CHECK(events[1].pid == 100);
    CHECK(events[1].user == "alice");
}

TEST_CASE("tar parse: error payload and wrong shape yield empty", "[tar][tree][parse]") {
    CHECK(parse_tar_process_output("error|database is locked\n").empty());
    // Missing the required `pid` column → refuse rather than guess.
    CHECK(parse_tar_process_output("__schema__|ts|action|ppid|name\n100|started|0|x\n").empty());
}

TEST_CASE("tar parse: tcp __schema__ output", "[tar][tree][parse]") {
    const std::string out =
        "__schema__|pid|process_name|proto|local_port|remote_addr|remote_port|state|ts|action\n"
        "100|bash|tcp|54321|1.2.3.4|443|ESTABLISHED|160|connected\n";
    auto conns = parse_tar_tcp_output(out);
    REQUIRE(conns.size() == 1);
    CHECK(conns[0].pid == 100);
    CHECK(conns[0].remote_addr == "1.2.3.4");
    CHECK(conns[0].remote_port == 443);
    CHECK(conns[0].state == "ESTABLISHED");
}

TEST_CASE("tar tree: basic parent/child reconstruction", "[tar][tree]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(110, "started", 100, 1, "bash", "alice"),
        ev(120, "started", 200, 100, "python", "alice"),
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    REQUIRE(t.roots.size() == 1);
    const TarProcNode& root = t.nodes[t.roots[0]];
    CHECK(root.pid == 1);
    REQUIRE(root.children.size() == 1);
    const TarProcNode& bash = t.nodes[root.children[0]];
    CHECK(bash.pid == 100);
    REQUIRE(bash.children.size() == 1);
    CHECK(t.nodes[bash.children[0]].pid == 200);
    CHECK(t.running_count == 3);
    CHECK(t.exited_count == 0);
}

TEST_CASE("tar tree: window overlap includes exited-in-window, excludes exited-before",
          "[tar][tree][window]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(100, "started", 60, 1, "early"),
        ev(120, "stopped", 60, 1, "early"), // exited 120 — before `from`
        ev(150, "started", 50, 1, "recent"),
        ev(160, "stopped", 50, 1, "recent"), // exited 160 — within window
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, /*from=*/155, /*to=*/2000, a);
    CHECK(find_pid(t, 60) == nullptr);          // exited before the window
    const TarProcNode* recent = find_pid(t, 50);
    REQUIRE(recent != nullptr);                 // exited inside the window → shown
    CHECK_FALSE(recent->running);
    CHECK(recent->exited_ts == 160);
    CHECK(find_pid(t, 1) != nullptr);           // long-running → always present
}

TEST_CASE("tar tree: long-running started before window still appears (running)",
          "[tar][tree][window]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(100, "started", 500, 1, "longproc"), // started long ago, never stops
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, /*from=*/1000, /*to=*/2000, a);
    const TarProcNode* lp = find_pid(t, 500);
    REQUIRE(lp != nullptr);
    CHECK(lp->running);
}

TEST_CASE("tar tree: to excludes later starts (point-in-time upper bound)", "[tar][tree][window]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(300, "started", 77, 1, "future"),
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, /*from=*/0, /*to=*/200, a);
    CHECK(find_pid(t, 77) == nullptr);
    CHECK(find_pid(t, 1) != nullptr);
}

TEST_CASE("tar tree: pid reuse yields two incarnations", "[tar][tree][reuse]") {
    std::vector<TarProcEvent> e{
        ev(50, "started", 1, 0, "systemd"),
        ev(100, "started", 100, 1, "bash"),
        ev(150, "stopped", 100, 1, "bash"),
        ev(200, "started", 100, 1, "powershell.exe"), // pid reused, still running
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    CHECK(count_pid(t, 100) == 2);
    const TarProcNode* run = find_pid(t, 100, /*running_pref=*/true);
    REQUIRE(run != nullptr);
    CHECK(run->running);
    CHECK(run->name == "powershell.exe");
    // Both incarnations parent to the single pid-1 root.
    const TarProcNode& root = t.nodes[t.roots[0]];
    CHECK(root.children.size() == 2);
}

TEST_CASE("tar tree: orphan whose parent is absent becomes a root", "[tar][tree]") {
    std::vector<TarProcEvent> e{ev(100, "started", 500, 400, "orphan")}; // ppid 400 absent
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    REQUIRE(t.roots.size() == 1);
    CHECK(t.nodes[t.roots[0]].pid == 500);
}

TEST_CASE("tar anomaly: suspicious parent->child flagged, benign parent not", "[tar][tree][anomaly]") {
    std::string evidence;
    CHECK(tar_is_suspicious_spawn("winword.exe", "powershell.exe", &evidence));
    CHECK(evidence.find("winword.exe") != std::string::npos);
    CHECK_FALSE(tar_is_suspicious_spawn("explorer.exe", "cmd.exe")); // benign — explorer excluded
    CHECK_FALSE(tar_is_suspicious_spawn("bash", "ls"));

    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(110, "started", 10, 1, "winword.exe", "bob"),
        ev(120, "started", 20, 10, "powershell.exe", "bob"),
        ev(130, "started", 40, 1, "explorer.exe"),
        ev(140, "started", 50, 40, "cmd.exe"),
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    const TarProcNode* ps = find_pid(t, 20);
    REQUIRE(ps != nullptr);
    CHECK(ps->anomaly);
    const TarProcNode* benign = find_pid(t, 50);
    REQUIRE(benign != nullptr);
    CHECK_FALSE(benign->anomaly);
    CHECK(t.anomaly_count == 1);
}

TEST_CASE("tar tree: full tree is never pruned (filtering is client-side)", "[tar][tree][anomaly]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(110, "started", 10, 1, "winword.exe"),
        ev(120, "started", 20, 10, "powershell.exe"), // the anomaly
        ev(130, "started", 30, 1, "sshd"),
        ev(140, "started", 40, 30, "bash"),
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    // Reconstruction keeps EVERY node (running/exited/anomalies filtering is a
    // client-side display concern); the flag is set but the tree is not pruned.
    CHECK(t.running_count == 5);
    CHECK(t.anomaly_count == 1);
    REQUIRE(t.roots.size() == 1);
    const TarProcNode& root = t.nodes[t.roots[0]];
    REQUIRE(root.children.size() == 2);          // BOTH winword and sshd remain
    CHECK(find_pid(t, 40) != nullptr);           // bash under sshd still present
}

TEST_CASE("tar render: rows carry data-state and data-anom for client filters",
          "[tar][tree][render]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(110, "started", 10, 1, "winword.exe"),
        ev(120, "started", 20, 10, "powershell.exe"), // anomaly, running
        ev(130, "started", 50, 1, "old"),
        ev(140, "stopped", 50, 1, "old"),             // exited
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    auto html = render_tar_tree_fragment(t, {}, "dev1", "0123456789abcdef0123456789abcdef", "linux");
    CHECK(html.find("data-state=\"running\"") != std::string::npos);
    CHECK(html.find("data-state=\"exited\"") != std::string::npos);
    CHECK(html.find("data-anom=\"1\"") != std::string::npos); // powershell flagged
}

TEST_CASE("tar render: inline network summary shows remote IP:port", "[tar][tree][render][net]") {
    std::vector<TarProcEvent> e{ev(100, "started", 1234, 1, "curl")};
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    std::vector<TarTcpConn> conns;
    TarTcpConn c;
    c.pid = 1234;
    c.proto = "tcp";
    c.remote_addr = "203.0.113.7"; // public
    c.remote_port = 443;
    c.local_port = 51000;
    c.state = "ESTABLISHED";
    conns.push_back(c);
    auto html = render_tar_tree_fragment(t, conns, "dev1", "0123456789abcdef0123456789abcdef", "linux");
    CHECK(html.find("203.0.113.7:443") != std::string::npos); // IP:port surfaced inline
    CHECK(html.find("tt-net") != std::string::npos);
    CHECK(html.find("tt-ep-pub") != std::string::npos);        // public endpoint highlighted
}

TEST_CASE("tar render: same-name siblings group past the threshold", "[tar][tree][render]") {
    std::vector<TarProcEvent> e{ev(100, "started", 1, 0, "services.exe")};
    for (std::uint32_t p = 2000; p < 2005; ++p) // 5 svchost.exe under services.exe
        e.push_back(ev(110, "started", p, 1, "svchost.exe"));
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    auto html = render_tar_tree_fragment(t, {}, "dev1", "0123456789abcdef0123456789abcdef", "windows");
    CHECK(html.find("tar-tree-group") != std::string::npos);
    CHECK(html.find("\xC3\x97" "5") != std::string::npos); // "×5" group count
}

TEST_CASE("tar render: few same-name siblings are not grouped", "[tar][tree][render]") {
    std::vector<TarProcEvent> e{ev(100, "started", 1, 0, "services.exe"),
                                ev(110, "started", 2000, 1, "svchost.exe"),
                                ev(110, "started", 2001, 1, "svchost.exe")}; // only 2
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    auto html = render_tar_tree_fragment(t, {}, "dev1", "0123456789abcdef0123456789abcdef", "windows");
    CHECK(html.find("tar-tree-group") == std::string::npos);
}

TEST_CASE("tar anchors: install = min ts, boot = latest root start", "[tar][tree][anchor]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(500, "started", 1, 0, "systemd"), // reboot — newer ppid==0 start
        ev(600, "started", 100, 1, "bash"),
    };
    auto a = compute_tar_anchors(e);
    CHECK(a.observed_since == 100);
    CHECK(a.install_ts == 100);
    CHECK(a.boot_ts == 500);
}

TEST_CASE("tar window: preset resolution", "[tar][tree][window]") {
    TarTreeAnchors a;
    a.observed_since = 100;
    a.install_ts = 100;
    a.boot_ts = 500;
    const std::int64_t now = 10000;

    CHECK(resolve_tar_window("1m", 0, 0, a, now).from_ts == now - 60);
    CHECK(resolve_tar_window("10m", 0, 0, a, now).from_ts == now - 600);
    CHECK(resolve_tar_window("1h", 0, 0, a, now).from_ts == now - 3600);
    CHECK(resolve_tar_window("1d", 0, 0, a, now).from_ts == 0); // now-86400 < 0 → clamped
    CHECK(resolve_tar_window("on_install", 0, 0, a, now).from_ts == 100);
    CHECK(resolve_tar_window("on_boot", 0, 0, a, now).from_ts == 500);
    CHECK(resolve_tar_window("garbage", 0, 0, a, now).from_ts == now - 600); // default 10m

    auto custom = resolve_tar_window("custom", 2000, 3000, a, now);
    CHECK(custom.from_ts == 2000);
    CHECK(custom.to_ts == 3000);
    auto blank = resolve_tar_window("custom", 0, 0, a, now);
    CHECK(blank.from_ts == 100);   // unset from → install
    CHECK(blank.to_ts == now);     // unset to → now
    auto reversed = resolve_tar_window("custom", 5000, 4000, a, now);
    CHECK(reversed.to_ts == reversed.from_ts); // reversed range collapses to a point
}

TEST_CASE("tar render: agent-controlled fields are HTML-escaped", "[tar][tree][render]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "<script>evil</script>", "us\"er"),
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    auto html = render_tar_tree_fragment(t, {}, "dev1", "0123456789abcdef0123456789abcdef", "linux");
    CHECK(html.find("<script>evil") == std::string::npos);
    CHECK(html.find("&lt;script&gt;evil") != std::string::npos);

    auto detail = render_tar_proc_detail(t.nodes[0], {}, "linux");
    CHECK(detail.find("<script>evil") == std::string::npos);
    CHECK(detail.find("&lt;script&gt;") != std::string::npos);
}

TEST_CASE("tar render: Windows names-only caption, Linux shows cmdline", "[tar][tree][render]") {
    TarProcNode n;
    n.pid = 42;
    n.ppid = 1;
    n.name = "proc";
    n.cmdline = "/usr/bin/proc --flag";
    n.running = true;
    n.start_known = true;
    n.started_ts = 100;

    auto win = render_tar_proc_detail(n, {}, "windows");
    CHECK(win.find("names-only on Windows") != std::string::npos);
    CHECK(win.find("/usr/bin/proc") == std::string::npos); // not surfaced on Windows

    auto lin = render_tar_proc_detail(n, {}, "linux");
    CHECK(lin.find("/usr/bin/proc --flag") != std::string::npos);
}
