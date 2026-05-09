#pragma once

/**
 * process_category.hpp -- Heuristic process classification for fleet viz
 *
 * Maps an executable basename + owning user to one of six categories used
 * by the /viz/fleet renderer to color interior process nodes:
 *   System    -- init, kthreadd, systemd, launchd, svchost, ...
 *   Browser   -- chrome, firefox, edge, safari, brave, ...
 *   Database  -- postgres, mysqld, mariadbd, redis-server, mongod, ...
 *   Web       -- nginx, apache, httpd, iisexpress, caddy, ...
 *   Runtime   -- java, python, node, dotnet, ruby, php-fpm, ...
 *   Other     -- everything not in the above tables
 *
 * Lookup is case-insensitive and matches the basename (no path / no
 * trailing exe extension on Windows). Designed for v1 -- intentionally
 * a fixed table rather than a YAML-loaded list because:
 *   1. Categories are visualization-only; misclassification just changes
 *      a node color, not a security or compliance decision.
 *   2. Fixed table => no runtime config surface => no operator footgun.
 *   3. Future PRs can swap to a config-loaded table without changing the
 *      classify() signature.
 *
 * Header-only and stateless so the JSON serializer in fleet_topology_types
 * can include it without a link dependency.
 *
 * TODO(PR 7+): consider relocating to sdk/include/yuzu/process_category.hpp
 * when the table stabilises so future agent-side classification (e.g. an
 * "exclude system processes" filter) can reach this enum without crossing
 * server/agent module boundaries.
 */

#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <string_view>

namespace yuzu::server {

enum class ProcessCategory { System, Browser, Database, Web, Runtime, Other };

inline std::string_view category_to_string(ProcessCategory c) {
    switch (c) {
    case ProcessCategory::System:
        return "system";
    case ProcessCategory::Browser:
        return "browser";
    case ProcessCategory::Database:
        return "database";
    case ProcessCategory::Web:
        return "web";
    case ProcessCategory::Runtime:
        return "runtime";
    case ProcessCategory::Other:
        return "other";
    }
    return "other";
}

namespace detail {

inline std::string lower_basename(std::string_view name) {
    // Strip leading directory if any
    auto slash = name.find_last_of("/\\");
    if (slash != std::string_view::npos)
        name.remove_prefix(slash + 1);
    // Strip Windows .exe suffix (case-insensitive)
    if (name.size() > 4) {
        auto tail = name.substr(name.size() - 4);
        if (tail[0] == '.' && (tail[1] == 'e' || tail[1] == 'E') &&
            (tail[2] == 'x' || tail[2] == 'X') && (tail[3] == 'e' || tail[3] == 'E')) {
            name.remove_suffix(4);
        }
    }
    std::string s(name);
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

} // namespace detail

/**
 * Classify a process by its executable basename and owning user.
 * The user argument is reserved for future heuristics (e.g., distinguishing
 * a system daemon running as root vs a user-launched copy of the same
 * binary). v1 ignores it but accepts it for forward compatibility.
 */
inline ProcessCategory classify(std::string_view exe_basename, std::string_view /*user*/ = {}) {
    auto name = detail::lower_basename(exe_basename);
    if (name.empty())
        return ProcessCategory::Other;

    // Database
    static constexpr std::array kDatabase = {
        "postgres",  "postgresql",   "psql",      "mysqld",        "mysql",
        "mariadbd",  "redis-server", "redis",     "mongod",        "mongo",
        "memcached", "etcd",         "cassandra", "elasticsearch", "clickhouse-server",
        "influxd",   "rethinkdb",    "cockroach", "yugabyted",     "scylla"};
    for (auto* k : kDatabase)
        if (name == k)
            return ProcessCategory::Database;

    // Browser
    static constexpr std::array kBrowser = {
        "chrome",  "chromium",    "firefox", "firefox-bin",   "msedge",
        "edge",    "safari",      "brave",   "brave-browser", "opera",
        "vivaldi", "tor-browser", "thorium", "googlechrome"};
    for (auto* k : kBrowser)
        if (name == k)
            return ProcessCategory::Browser;

    // Web server / proxy
    static constexpr std::array kWeb = {"nginx",   "apache2", "httpd", "iisexpress", "caddy",
                                        "traefik", "haproxy", "envoy", "lighttpd",   "varnishd"};
    for (auto* k : kWeb)
        if (name == k)
            return ProcessCategory::Web;

    // Runtime / interpreter
    static constexpr std::array kRuntime = {
        "java",     "javaw",  "python",  "python2", "python3", "node", "nodejs", "ruby",
        "perl",     "php",    "php-fpm", "php-cgi", "dotnet",  "mono", "erl",    "beam",
        "beam.smp", "elixir", "iex",     "lua",     "rscript", "go",   "deno",   "bun"};
    for (auto* k : kRuntime)
        if (name == k)
            return ProcessCategory::Runtime;

    // System / init / service host
    static constexpr std::array kSystem = {"init",
                                           "systemd",
                                           "systemd-journal",
                                           "systemd-logind",
                                           "systemd-resolved",
                                           "systemd-timesyn",
                                           "systemd-udevd",
                                           "kthreadd",
                                           "ksoftirqd",
                                           "rcu_sched",
                                           "kworker",
                                           "migration",
                                           "launchd",
                                           "kernel_task",
                                           "windowserver",
                                           "mds",
                                           "mds_stores",
                                           "svchost",
                                           "lsass",
                                           "winlogon",
                                           "csrss",
                                           "smss",
                                           "wininit",
                                           "services",
                                           "spoolsv",
                                           "dwm",
                                           "explorer",
                                           "fontdrvhost",
                                           "syslogd",
                                           "cron",
                                           "crond",
                                           "rsyslogd",
                                           "klogd",
                                           "auditd",
                                           "dbus-daemon",
                                           "dbus",
                                           "udevd",
                                           "agetty",
                                           "login"};
    for (auto* k : kSystem)
        if (name == k)
            return ProcessCategory::System;

    return ProcessCategory::Other;
}

} // namespace yuzu::server
