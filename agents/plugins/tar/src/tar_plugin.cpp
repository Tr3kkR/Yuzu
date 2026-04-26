/**
 * tar_plugin.cpp -- Timeline Activity Record (TAR) plugin for Yuzu
 *
 * Continuously captures system state snapshots (processes, network connections,
 * services, user sessions) and records changes as timestamped events in a local
 * SQLite database. Enables retrospective "what happened on this machine" queries
 * without requiring pre-configured logging.
 *
 * Actions:
 *   collect_fast  -- Snapshot processes + network, diff, record events (60s interval)
 *   collect_slow  -- Snapshot services + users, diff, record events (300s interval)
 *   status        -- Return db stats (count, oldest, newest, disk size, config)
 *   query         -- Query events by time range with optional type filter
 *   export        -- Export events as JSON array
 *   snapshot      -- Force an immediate full snapshot (all 4 collectors)
 *   configure     -- Update retention_days, intervals, redaction patterns
 *
 * Data flow:
 *   trigger fires -> enumerate current state -> load previous state from tar_state
 *   -> compute diff -> insert events -> save current state
 */

#include "tar_collectors.hpp"
#include "tar_db.hpp"
#include "tar_schema_registry.hpp"
#include "tar_aggregator.hpp"
#include "tar_sql_executor.hpp"

#include <yuzu/agent/process_enum.hpp>
#include <yuzu/plugin.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

using json = nlohmann::json;

int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

int64_t next_snapshot_id() {
    static std::atomic<int64_t> counter{0};
    return now_epoch_seconds() * 1000 + counter.fetch_add(1, std::memory_order_relaxed) % 1000;
}

// ── State serialization helpers ──────────────────────────────────────────────

json processes_to_json(const std::vector<yuzu::agent::ProcessInfo>& procs) {
    json arr = json::array();
    for (const auto& p : procs) {
        arr.push_back({{"pid", p.pid}, {"ppid", p.ppid}, {"name", p.name},
                        {"cmdline", p.cmdline}, {"user", p.user}});
    }
    return arr;
}

std::vector<yuzu::agent::ProcessInfo> json_to_processes(const std::string& s) {
    std::vector<yuzu::agent::ProcessInfo> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::agent::ProcessInfo p;
            p.pid = j.value("pid", 0u);
            p.ppid = j.value("ppid", 0u);
            p.name = j.value("name", "");
            p.cmdline = j.value("cmdline", "");
            p.user = j.value("user", "");
            result.push_back(std::move(p));
        }
    } catch (...) {}
    return result;
}

json connections_to_json(const std::vector<yuzu::tar::NetConnection>& conns) {
    json arr = json::array();
    for (const auto& c : conns) {
        arr.push_back({{"proto", c.proto}, {"local_addr", c.local_addr},
                        {"local_port", c.local_port}, {"remote_addr", c.remote_addr},
                        {"remote_port", c.remote_port}, {"state", c.state},
                        {"pid", c.pid}, {"process_name", c.process_name}});
    }
    return arr;
}

std::vector<yuzu::tar::NetConnection> json_to_connections(const std::string& s) {
    std::vector<yuzu::tar::NetConnection> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::tar::NetConnection c;
            c.proto = j.value("proto", "");
            c.local_addr = j.value("local_addr", "");
            c.local_port = j.value("local_port", 0);
            c.remote_addr = j.value("remote_addr", "");
            c.remote_port = j.value("remote_port", 0);
            c.state = j.value("state", "");
            c.pid = j.value("pid", 0u);
            c.process_name = j.value("process_name", "");
            result.push_back(std::move(c));
        }
    } catch (...) {}
    return result;
}

json services_to_json(const std::vector<yuzu::tar::ServiceInfo>& svcs) {
    json arr = json::array();
    for (const auto& s : svcs) {
        arr.push_back({{"name", s.name}, {"display_name", s.display_name},
                        {"status", s.status}, {"startup_type", s.startup_type}});
    }
    return arr;
}

std::vector<yuzu::tar::ServiceInfo> json_to_services(const std::string& s) {
    std::vector<yuzu::tar::ServiceInfo> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::tar::ServiceInfo si;
            si.name = j.value("name", "");
            si.display_name = j.value("display_name", "");
            si.status = j.value("status", "");
            si.startup_type = j.value("startup_type", "");
            result.push_back(std::move(si));
        }
    } catch (...) {}
    return result;
}

json users_to_json(const std::vector<yuzu::tar::UserSession>& users) {
    json arr = json::array();
    for (const auto& u : users) {
        arr.push_back({{"user", u.user}, {"domain", u.domain},
                        {"logon_type", u.logon_type}, {"session_id", u.session_id}});
    }
    return arr;
}

std::vector<yuzu::tar::UserSession> json_to_users(const std::string& s) {
    std::vector<yuzu::tar::UserSession> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::tar::UserSession u;
            u.user = j.value("user", "");
            u.domain = j.value("domain", "");
            u.logon_type = j.value("logon_type", "");
            u.session_id = j.value("session_id", "");
            result.push_back(std::move(u));
        }
    } catch (...) {}
    return result;
}

// ── Redaction pattern loading ────────────────────────────────────────────────

std::vector<std::string> load_redaction_patterns(yuzu::tar::TarDatabase& db) {
    auto stored = db.get_config("redaction_patterns");
    if (stored.empty())
        return {"*password*", "*secret*", "*token*", "*api_key*", "*credential*"};
    try {
        auto arr = json::parse(stored);
        std::vector<std::string> patterns;
        for (const auto& p : arr) {
            patterns.push_back(p.get<std::string>());
        }
        return patterns;
    } catch (...) {
        return {"*password*", "*secret*", "*token*", "*api_key*", "*credential*"};
    }
}

// Per-source enable/disable (issue #59). Default = enabled.
bool source_enabled(yuzu::tar::TarDatabase& db, std::string_view source) {
    return db.get_config(std::format("{}_enabled", source), "true") != "false";
}

// Process stabilization exclusion patterns (issue #59). Empty = no exclusions.
std::vector<std::string> load_stabilization_exclusions(yuzu::tar::TarDatabase& db) {
    auto stored = db.get_config("process_stabilization_exclusions");
    if (stored.empty())
        return {};
    try {
        auto arr = json::parse(stored);
        std::vector<std::string> patterns;
        for (const auto& p : arr) {
            patterns.push_back(p.get<std::string>());
        }
        return patterns;
    } catch (...) {
        return {};
    }
}

} // namespace

class TarPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "tar"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Timeline Activity Record -- continuous system state change tracking";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"status", "query", "snapshot", "export",
                                      "configure", "collect_fast", "collect_slow",
                                      "rollup", "sql", "compatibility", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        plugin_ctx_ = ctx.raw();

        // Determine data directory
        auto data_dir = ctx.get_config("agent.data_dir");
        std::string db_dir;
        if (data_dir.empty()) {
#ifdef _WIN32
            db_dir = "C:\\ProgramData\\yuzu\\agent";
#else
            db_dir = "/var/lib/yuzu/agent";
#endif
        } else {
            db_dir = std::string{data_dir};
        }

        auto db_path = std::filesystem::path{db_dir} / "tar.db";
        auto result = yuzu::tar::TarDatabase::open(db_path);
        if (!result) {
            return std::unexpected(
                yuzu::PluginError{1, std::format("TAR: failed to open db: {}", result.error())});
        }
        db_ = std::make_unique<yuzu::tar::TarDatabase>(std::move(*result));

        // Load config
        int fast_interval = 60;
        int slow_interval = 300;
        auto fast_str = db_->get_config("fast_interval_seconds", "60");
        auto slow_str = db_->get_config("slow_interval_seconds", "300");
        try { fast_interval = std::stoi(fast_str); } catch (...) {}
        try { slow_interval = std::stoi(slow_str); } catch (...) {}

        // Register triggers
        auto fast_config = std::format(
            R"({{"interval_seconds":{},"plugin":"tar","action":"collect_fast","parameters":{{}}}})",
            fast_interval);
        ctx.register_trigger("tar.fast", "interval", fast_config);

        auto slow_config = std::format(
            R"({{"interval_seconds":{},"plugin":"tar","action":"collect_slow","parameters":{{}}}})",
            slow_interval);
        ctx.register_trigger("tar.slow", "interval", slow_config);

        // Register rollup trigger (15-minute aggregation cycle)
        auto rollup_config = std::format(
            R"({{"interval_seconds":900,"plugin":"tar","action":"rollup","parameters":{{}}}})"
        );
        ctx.register_trigger("tar.rollup", "interval", rollup_config);

        spdlog::info("TAR plugin initialized (fast={}s, slow={}s, db={})",
                     fast_interval, slow_interval, db_path.string());
        return {};
    }

    void shutdown(yuzu::PluginContext& ctx) noexcept override {
        ctx.unregister_trigger("tar.fast");
        ctx.unregister_trigger("tar.slow");
        ctx.unregister_trigger("tar.rollup");
        db_.reset();
        spdlog::info("TAR plugin shut down");
    }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (!db_) {
            ctx.write_output("error|TAR database not initialized");
            return 1;
        }

        if (action == "collect_fast")  return do_collect_fast(ctx);
        if (action == "collect_slow")  return do_collect_slow(ctx);
        if (action == "status")        return do_status(ctx);
        if (action == "query")         return do_query(ctx, params);
        if (action == "export")        return do_export(ctx, params);
        if (action == "snapshot")      return do_snapshot(ctx);
        if (action == "configure")     return do_configure(ctx, params);
        if (action == "rollup")        return do_rollup(ctx);
        if (action == "sql")           return do_sql(ctx, params);
        if (action == "compatibility") return do_compatibility(ctx);

        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
    }

private:
    YuzuPluginContext* plugin_ctx_{nullptr};
    std::unique_ptr<yuzu::tar::TarDatabase> db_;
    std::mutex collect_mu_;     // Protects the state read-diff-write sequence in collect methods

    // ── collect_fast: processes + network ─────────────────────────────────────
    // Unlocked implementation -- caller must hold collect_mu_
    int collect_fast_impl(yuzu::CommandContext& ctx) {
        auto ts = now_epoch_seconds();
        auto snap_id = next_snapshot_id();
        auto redaction = load_redaction_patterns(*db_);
        auto stab_excl = load_stabilization_exclusions(*db_);
        int total_events = 0;

        // Process diff (C6: check insert return, abort state save on failure)
        // Per-source enable gate (issue #59): if disabled, skip both the
        // diff and the state save so that re-enabling later starts from a
        // clean baseline rather than diffing against a frozen snapshot.
        if (source_enabled(*db_, "process")) {
            auto current = yuzu::agent::enumerate_processes();

            // Stabilization exclusions: drop processes whose name matches any
            // exclusion pattern. The patterns reuse the same glob semantics
            // as redaction (case-insensitive substring with optional '*' on
            // either side stripped). Excluded processes never enter the
            // diff, so their birth/death events are silently dropped — the
            // documented forensic-completeness trade-off.
            if (!stab_excl.empty()) {
                std::erase_if(current, [&](const auto& p) {
                    return yuzu::tar::should_redact(p.name, stab_excl);
                });
            }

            auto prev_json = db_->get_state("process");
            auto previous = json_to_processes(prev_json);

            auto typed = yuzu::tar::compute_process_events(previous, current, ts, snap_id, redaction);
            if (!typed.empty()) {
                if (!db_->insert_process_events(typed)) {
                    spdlog::error("TAR: failed to insert process events, skipping state save");
                    ctx.write_output("error|process insert failed");
                    return 1;
                }
                total_events += static_cast<int>(typed.size());
            }

            db_->set_state("process", processes_to_json(current).dump());
        }

        // Network diff
        if (source_enabled(*db_, "tcp")) {
            auto current = yuzu::tar::enumerate_connections();
            auto prev_json = db_->get_state("network");
            auto previous = json_to_connections(prev_json);

            auto typed = yuzu::tar::compute_network_events(previous, current, ts, snap_id);
            if (!typed.empty()) {
                if (!db_->insert_network_events(typed)) {
                    spdlog::error("TAR: failed to insert network events, skipping state save");
                    ctx.write_output("error|network insert failed");
                    return 1;
                }
                total_events += static_cast<int>(typed.size());
            }

            db_->set_state("network", connections_to_json(current).dump());
        }

        ctx.write_output(std::format("tar|collect_fast|{}|events_recorded", total_events));
        return 0;
    }

    int do_collect_fast(yuzu::CommandContext& ctx) {
        std::lock_guard lock(collect_mu_);
        return collect_fast_impl(ctx);
    }

    // ── collect_slow: services + users ────────────────────────────────────────
    // Unlocked implementation -- caller must hold collect_mu_
    int collect_slow_impl(yuzu::CommandContext& ctx) {
        auto ts = now_epoch_seconds();
        auto snap_id = next_snapshot_id();
        int total_events = 0;

        // Service diff (C6: check insert return)
        if (source_enabled(*db_, "service")) {
            auto current = yuzu::tar::enumerate_services();
            auto prev_json = db_->get_state("service");
            auto previous = json_to_services(prev_json);

            auto typed = yuzu::tar::compute_service_events(previous, current, ts, snap_id);
            if (!typed.empty()) {
                if (!db_->insert_service_events(typed)) {
                    spdlog::error("TAR: failed to insert service events, skipping state save");
                    ctx.write_output("error|service insert failed");
                    return 1;
                }
                total_events += static_cast<int>(typed.size());
            }

            db_->set_state("service", services_to_json(current).dump());
        }

        // User diff
        if (source_enabled(*db_, "user")) {
            auto current = yuzu::tar::enumerate_users();
            auto prev_json = db_->get_state("user");
            auto previous = json_to_users(prev_json);

            auto typed = yuzu::tar::compute_user_events(previous, current, ts, snap_id);
            if (!typed.empty()) {
                if (!db_->insert_user_events(typed)) {
                    spdlog::error("TAR: failed to insert user events, skipping state save");
                    ctx.write_output("error|user insert failed");
                    return 1;
                }
                total_events += static_cast<int>(typed.size());
            }

            db_->set_state("user", users_to_json(current).dump());
        }

        // Legacy purge removed — retention is now handled by run_retention() in rollup action

        ctx.write_output(std::format("tar|collect_slow|{}|events_recorded", total_events));
        return 0;
    }

    int do_collect_slow(yuzu::CommandContext& ctx) {
        std::lock_guard lock(collect_mu_);
        return collect_slow_impl(ctx);
    }

    // ── status action ─────────────────────────────────────────────────────────

    int do_status(yuzu::CommandContext& ctx) {
        auto s = db_->stats();
        ctx.write_output(std::format("record_count|{}", s.record_count));
        ctx.write_output(std::format("oldest_timestamp|{}", s.oldest_timestamp));
        ctx.write_output(std::format("newest_timestamp|{}", s.newest_timestamp));
        ctx.write_output(std::format("db_size_bytes|{}", s.db_size_bytes));
        ctx.write_output(std::format("retention_days|{}", s.retention_days));

        // Per-source enable/disable state (issue #59). Default = enabled, so
        // operators that never call `configure` see the steady-state behavior.
        for (const auto& src : yuzu::tar::capture_sources()) {
            std::string key = std::format("{}_enabled", src.name);
            auto val = db_->get_config(key, "true");
            ctx.write_output(std::format("config|{}|{}", key, val));
        }
        // Currently-configured network capture method (defaults to "polling").
        auto net_method = db_->get_config("network_capture_method", "polling");
        ctx.write_output(std::format("config|network_capture_method|{}", net_method));
        return 0;
    }

    // ── compatibility action (issue #59) ──────────────────────────────────────
    //
    // Emits one row per (source, OS) describing how the source captures data
    // on that platform and any known constraint. Pipe-delimited so the
    // existing dashboard renderer can show it as a table without a JSON
    // codec change.
    int do_compatibility(yuzu::CommandContext& ctx) {
        ctx.write_output(
            "header|source|os|status|capture_method|notes");
        for (const auto& src : yuzu::tar::capture_sources()) {
            for (const auto& os : src.os_support) {
                std::string_view status_str;
                switch (os.status) {
                case yuzu::tar::OsSupportStatus::kSupported:
                    status_str = "supported"; break;
                case yuzu::tar::OsSupportStatus::kSupportedConstrained:
                    status_str = "constrained"; break;
                case yuzu::tar::OsSupportStatus::kPlanned:
                    status_str = "planned"; break;
                case yuzu::tar::OsSupportStatus::kUnsupported:
                    status_str = "unsupported"; break;
                }
                ctx.write_output(std::format("row|{}|{}|{}|{}|{}",
                                              src.name, os.os, status_str,
                                              os.capture_method, os.notes));
            }
        }
        return 0;
    }

    // ── query action ──────────────────────────────────────────────────────────

    int do_query(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto from_str = params.get("from", "0");
        auto to_str = params.get("to");
        auto type_filter = std::string{params.get("type")};
        auto limit_str = params.get("limit", "1000");

        int64_t from = 0;
        int64_t to = now_epoch_seconds();
        int limit = 1000;

        try { from = std::stoll(std::string{from_str}); } catch (...) {
            ctx.write_output("error|invalid 'from' parameter (must be epoch seconds)");
            return 1;
        }
        if (!to_str.empty()) {
            try { to = std::stoll(std::string{to_str}); } catch (...) {
                ctx.write_output("error|invalid 'to' parameter (must be epoch seconds)");
                return 1;
            }
        }
        try { limit = std::stoi(std::string{limit_str}); } catch (...) {}

        if (from < 0 || to < 0) {
            ctx.write_output("error|timestamps must be non-negative");
            return 1;
        }
        if (from > to) {
            ctx.write_output("error|'from' must be <= 'to'");
            return 1;
        }
        if (limit <= 0 || limit > 10000)
            limit = 1000;

        // Query typed live tables (replaces legacy tar_events)
        auto from_s = std::to_string(from);
        auto to_s = std::to_string(to);
        auto lim_s = std::to_string(limit);
        std::string where = " WHERE ts >= " + from_s + " AND ts <= " + to_s;
        std::string tail = " ORDER BY ts ASC LIMIT " + lim_s;

        std::string sql;
        if (type_filter == "process") {
            sql = "SELECT ts, 'process' AS event_type, action, snapshot_id, "
                  "'' AS detail_json FROM process_live" + where + tail;
        } else if (type_filter == "network") {
            sql = "SELECT ts, 'network' AS event_type, action, snapshot_id, "
                  "'' AS detail_json FROM tcp_live" + where + tail;
        } else if (type_filter == "service") {
            sql = "SELECT ts, 'service' AS event_type, action, snapshot_id, "
                  "'' AS detail_json FROM service_live" + where + tail;
        } else if (type_filter == "user") {
            sql = "SELECT ts, 'user' AS event_type, action, snapshot_id, "
                  "'' AS detail_json FROM user_live" + where + tail;
        } else {
            sql = "SELECT * FROM ("
                  "SELECT ts, 'process' AS event_type, action, snapshot_id, '' AS detail_json FROM process_live" + where +
                  " UNION ALL "
                  "SELECT ts, 'network', action, snapshot_id, '' FROM tcp_live" + where +
                  " UNION ALL "
                  "SELECT ts, 'service', action, snapshot_id, '' FROM service_live" + where +
                  " UNION ALL "
                  "SELECT ts, 'user', action, snapshot_id, '' FROM user_live" + where +
                  ")" + tail;
        }

        auto query_result = db_->execute_query(sql);
        if (!query_result) {
            ctx.write_output(std::format("error|{}", query_result.error()));
            return 1;
        }
        for (const auto& row : query_result->rows) {
            std::string line;
            for (size_t i = 0; i < row.size(); ++i) {
                if (i > 0) line += '|';
                line += row[i];
            }
            ctx.write_output(line);
        }
        ctx.write_output(std::format("total|{}", query_result->rows.size()));
        return 0;
    }

    // ── export action (JSON array output) ─────────────────────────────────────

    int do_export(yuzu::CommandContext& ctx, yuzu::Params params) {
        // Export delegates to the sql action with a JSON wrapper
        auto type_filter = std::string{params.get("type")};
        auto from_str = params.get("from", "0");
        auto to_str = params.get("to");
        auto limit_str = params.get("limit", "1000");

        int64_t from = 0;
        int64_t to = now_epoch_seconds();
        int limit = 1000;

        try { from = std::stoll(std::string{from_str}); } catch (...) {}
        if (!to_str.empty()) {
            try { to = std::stoll(std::string{to_str}); } catch (...) {}
        }
        try { limit = std::stoi(std::string{limit_str}); } catch (...) {}
        if (limit <= 0 || limit > 10000) limit = 1000;

        // Pick the right live table (HP-5: handle empty filter and unknown types)
        std::string sql;
        if (type_filter.empty()) {
            // Export from all live tables
            sql = std::format(
                "SELECT * FROM ("
                "SELECT 'process' AS source, * FROM process_live WHERE ts >= {} AND ts <= {} UNION ALL "
                "SELECT 'network', * FROM tcp_live WHERE ts >= {} AND ts <= {} UNION ALL "
                "SELECT 'service', * FROM service_live WHERE ts >= {} AND ts <= {} UNION ALL "
                "SELECT 'user', * FROM user_live WHERE ts >= {} AND ts <= {}"
                ") ORDER BY ts ASC LIMIT {}",
                from, to, from, to, from, to, from, to, limit);
        } else {
            std::string table;
            if (type_filter == "process") table = "process_live";
            else if (type_filter == "network") table = "tcp_live";
            else if (type_filter == "service") table = "service_live";
            else if (type_filter == "user") table = "user_live";
            else {
                ctx.write_output(std::format("error|unknown type filter: {}", type_filter));
                return 1;
            }
            sql = std::format("SELECT * FROM {} WHERE ts >= {} AND ts <= {} ORDER BY ts ASC LIMIT {}",
                              table, from, to, limit);
        }

        auto query_result = db_->execute_query(sql);
        if (!query_result) {
            ctx.write_output(std::format("error|{}", query_result.error()));
            return 1;
        }

        json arr = json::array();
        for (const auto& row : query_result->rows) {
            json obj;
            for (size_t i = 0; i < query_result->columns.size() && i < row.size(); ++i) {
                obj[query_result->columns[i]] = row[i];
            }
            arr.push_back(std::move(obj));
        }

        ctx.write_output(arr.dump());
        return 0;
    }

    // ── snapshot action (force immediate full collection) ─────────────────────

    int do_snapshot(yuzu::CommandContext& ctx) {
        std::lock_guard lock(collect_mu_);
        collect_fast_impl(ctx);
        collect_slow_impl(ctx);
        ctx.write_output("tar|snapshot|complete");
        return 0;
    }

    // ── configure action ──────────────────────────────────────────────────────

    int do_configure(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto retention = params.get("retention_days");
        auto fast_interval = params.get("fast_interval");
        auto slow_interval = params.get("slow_interval");
        auto redaction = params.get("redaction_patterns");

        bool changed = false;
        int fast_secs = 0;
        int slow_secs = 0;
        int days = 0;

        // M13: Validate ALL parameters BEFORE writing any to the database
        if (!retention.empty()) {
            try { days = std::stoi(std::string{retention}); } catch (...) {}
            if (days < 1 || days > 365) {
                ctx.write_output("error|retention_days must be 1-365");
                return 1;
            }
        }

        if (!fast_interval.empty()) {
            try { fast_secs = std::stoi(std::string{fast_interval}); } catch (...) {}
            if (fast_secs < 10 || fast_secs > 3600) {
                ctx.write_output("error|fast_interval must be 10-3600 seconds");
                return 1;
            }
        }

        if (!slow_interval.empty()) {
            try { slow_secs = std::stoi(std::string{slow_interval}); } catch (...) {}
            if (slow_secs < 30 || slow_secs > 7200) {
                ctx.write_output("error|slow_interval must be 30-7200 seconds");
                return 1;
            }
        }

        // Cross-field validation BEFORE any writes
        if (fast_secs > 0 && slow_secs > 0 && fast_secs >= slow_secs) {
            ctx.write_output("error|fast_interval must be less than slow_interval");
            return 1;
        }

        // Now persist all validated values
        if (days > 0) {
            db_->set_config("retention_days", std::string{retention});
            ctx.write_output(std::format("config|retention_days|{}", retention));
            changed = true;
        }

        if (fast_secs > 0) {
            db_->set_config("fast_interval_seconds", std::string{fast_interval});
            ctx.write_output(std::format("config|fast_interval_seconds|{}", fast_interval));
            changed = true;
        }

        if (slow_secs > 0) {
            db_->set_config("slow_interval_seconds", std::string{slow_interval});
            ctx.write_output(std::format("config|slow_interval_seconds|{}", slow_interval));
            changed = true;
        }

        if (!redaction.empty()) {
            // Validate it's a JSON array of non-empty strings
            try {
                auto arr = json::parse(std::string{redaction});
                if (!arr.is_array()) {
                    ctx.write_output("error|redaction_patterns must be a JSON array of strings");
                    return 1;
                }
                for (const auto& elem : arr) {
                    if (!elem.is_string() || elem.get<std::string>().empty()) {
                        ctx.write_output("error|redaction_patterns must contain only non-empty strings");
                        return 1;
                    }
                }
                db_->set_config("redaction_patterns", std::string{redaction});
                ctx.write_output(std::format("config|redaction_patterns|{}", redaction));
                changed = true;
            } catch (...) {
                ctx.write_output("error|redaction_patterns must be valid JSON array");
                return 1;
            }
        }

        // ── Per-source enable/disable (issue #59) ─────────────────────────────
        // Operators can disable any of the four collectors on a host without
        // editing source. Disabled collectors short-circuit in
        // collect_fast/slow but still permit `query` against existing rows
        // (so historical data remains readable while new captures stop).
        for (const auto& src : yuzu::tar::capture_sources()) {
            std::string key = std::format("{}_enabled", src.name);
            auto val = params.get(key);
            if (val.empty()) continue;
            std::string v{val};
            if (v != "true" && v != "false") {
                ctx.write_output(std::format(
                    "error|{} must be 'true' or 'false'", key));
                return 1;
            }
            db_->set_config(key, v);
            ctx.write_output(std::format("config|{}|{}", key, v));
            changed = true;
        }

        // ── Network capture method surface (issue #59) ───────────────────────
        // Today only "polling" is wired. ETW (Windows) and Endpoint Security
        // (macOS) are accepted-and-stored values per the schema registry's
        // OsSupport metadata so an operator can pre-stage the configuration,
        // but the collector continues to use polling until the relevant
        // implementation lands. Validation rejects unknown methods so a typo
        // does not silently re-default to polling.
        if (auto m = params.get("network_capture_method"); !m.empty()) {
            std::string method{m};
            // "polling" is a sentinel meaning "use the platform default" —
            // the only mechanism actually wired today. It is intentionally
            // accepted unconditionally even though no os_support row carries
            // it as a capture_method (the per-OS rows describe the underlying
            // platform API: iphlpapi / procfs / proc_pidfdinfo). Without this
            // special case `tar.status` would report `polling` as the default
            // but `tar.configure network_capture_method=polling` would be
            // rejected — the round trip would be broken (governance C-1 /
            // QA Finding 2).
            if (method != "polling") {
                auto accepted = yuzu::tar::accepted_capture_methods("tcp");
                if (std::find(accepted.begin(), accepted.end(), method) == accepted.end()) {
                    std::string list = "polling";
                    for (const auto& m2 : accepted) {
                        list += ",";
                        list += m2;
                    }
                    ctx.write_output(std::format(
                        "error|network_capture_method '{}' is not accepted (must be one of: {})",
                        method, list));
                    return 1;
                }
                // Surface that no kernel-event collector is wired yet so an
                // operator pre-staging 'etw' / 'endpoint_security' isn't
                // surprised that the collector keeps polling under the hood.
                ctx.write_output(std::format(
                    "warn|network_capture_method '{}' accepted but not yet "
                    "implemented; collector will continue polling",
                    method));
            }
            db_->set_config("network_capture_method", method);
            ctx.write_output(std::format("config|network_capture_method|{}", method));
            changed = true;
        }

        // ── Process stabilization exclusions (issue #59) ─────────────────────
        // List of process-name glob patterns whose churn should be excluded
        // from process events. Useful for noisy short-lived helpers (CI
        // runners, IDE indexers, telemetry agents) that produce thousands
        // of birth/death rows per minute and dwarf the actual process
        // activity an operator wants to see. Trade-off: forensic completeness
        // is reduced — anything matching these patterns is invisible to TAR.
        if (auto exc = params.get("process_stabilization_exclusions"); !exc.empty()) {
            try {
                auto arr = json::parse(std::string{exc});
                if (!arr.is_array()) {
                    ctx.write_output(
                        "error|process_stabilization_exclusions must be a JSON array");
                    return 1;
                }
                for (const auto& elem : arr) {
                    if (!elem.is_string() || elem.get<std::string>().empty()) {
                        ctx.write_output(
                            "error|process_stabilization_exclusions must contain only "
                            "non-empty strings");
                        return 1;
                    }
                }
                db_->set_config("process_stabilization_exclusions", std::string{exc});
                ctx.write_output(
                    std::format("config|process_stabilization_exclusions|{}", exc));
                changed = true;
            } catch (...) {
                ctx.write_output(
                    "error|process_stabilization_exclusions must be valid JSON array");
                return 1;
            }
        }

        if (!changed) {
            ctx.write_output("error|no valid configuration parameters provided");
            return 1;
        }

        // Re-register triggers with new intervals if changed
        if (fast_secs > 0 || slow_secs > 0) {
            yuzu::PluginContext pctx{plugin_ctx_};
            if (fast_secs > 0) {
                pctx.unregister_trigger("tar.fast");
                auto cfg = std::format(R"({{"interval_seconds":{},"plugin":"tar","action":"collect_fast"}})", fast_secs);
                pctx.register_trigger("tar.fast", "interval", cfg);
                ctx.write_output(std::format("trigger|tar.fast|re-registered|{}s", fast_secs));
            }
            if (slow_secs > 0) {
                pctx.unregister_trigger("tar.slow");
                auto cfg = std::format(R"({{"interval_seconds":{},"plugin":"tar","action":"collect_slow"}})", slow_secs);
                pctx.register_trigger("tar.slow", "interval", cfg);
                ctx.write_output(std::format("trigger|tar.slow|re-registered|{}s", slow_secs));
            }
        }

        ctx.write_output("status|ok");
        return 0;
    }

    // ── rollup action (aggregation engine) ───────────────────────────────────

    int do_rollup(yuzu::CommandContext& ctx) {
        // No collect_mu_ needed — rollup operates on aggregate tables, not live-state diffs.
        // The SQLite-level mutex (db_->mu_) provides thread safety.
        auto ts = now_epoch_seconds();
        int total = yuzu::tar::run_aggregation(*db_, ts);
        yuzu::tar::run_retention(*db_, ts);
        ctx.write_output(std::format("tar|rollup|{}|rows_aggregated", total));
        return 0;
    }

    // ── sql action (warehouse query engine) ──────────────────────────────────

    int do_sql(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto sql_param = std::string{params.get("sql")};
        if (sql_param.empty()) {
            ctx.write_output("error|missing required 'sql' parameter");
            return 1;
        }

        auto validated = yuzu::tar::validate_and_translate_sql(sql_param);
        if (!validated) {
            ctx.write_output(std::format("error|{}", validated.error()));
            return 1;
        }

        auto query_result = db_->execute_query(*validated);
        if (!query_result) {
            ctx.write_output(std::format("error|{}", query_result.error()));
            return 1;
        }
        auto& result = *query_result;

        // Output schema line
        std::string schema_line = "__schema__";
        for (const auto& col : result.columns)
            schema_line += "|" + col;
        ctx.write_output(schema_line);

        // Output data rows
        for (const auto& row : result.rows) {
            std::string line;
            for (size_t i = 0; i < row.size(); ++i) {
                if (i > 0) line += '|';
                line += row[i];
            }
            ctx.write_output(line);
        }

        ctx.write_output(std::format("__total__|{}", result.rows.size()));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(TarPlugin)
