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
                                      "configure", "collect_fast", "collect_slow", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
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

        spdlog::info("TAR plugin initialized (fast={}s, slow={}s, db={})",
                     fast_interval, slow_interval, db_path.string());
        return {};
    }

    void shutdown(yuzu::PluginContext& ctx) noexcept override {
        ctx.unregister_trigger("tar.fast");
        ctx.unregister_trigger("tar.slow");
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

        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
    }

private:
    std::unique_ptr<yuzu::tar::TarDatabase> db_;
    std::mutex collect_mu_;     // Protects the state read-diff-write sequence in collect methods
    int64_t last_purge_time_{0};

    // ── collect_fast: processes + network ─────────────────────────────────────
    // Unlocked implementation -- caller must hold collect_mu_
    int collect_fast_impl(yuzu::CommandContext& ctx) {
        auto ts = now_epoch_seconds();
        auto snap_id = next_snapshot_id();
        auto redaction = load_redaction_patterns(*db_);
        int total_events = 0;

        // Process diff
        {
            auto current = yuzu::agent::enumerate_processes();
            auto prev_json = db_->get_state("process");
            auto previous = json_to_processes(prev_json);

            auto events = yuzu::tar::compute_process_diff(previous, current, ts, snap_id, redaction);
            if (!events.empty()) {
                db_->insert_events(events);
                total_events += static_cast<int>(events.size());
            }

            db_->set_state("process", processes_to_json(current).dump());
        }

        // Network diff
        {
            auto current = yuzu::tar::enumerate_connections();
            auto prev_json = db_->get_state("network");
            auto previous = json_to_connections(prev_json);

            auto events = yuzu::tar::compute_network_diff(previous, current, ts, snap_id);
            if (!events.empty()) {
                db_->insert_events(events);
                total_events += static_cast<int>(events.size());
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

        // Service diff
        {
            auto current = yuzu::tar::enumerate_services();
            auto prev_json = db_->get_state("service");
            auto previous = json_to_services(prev_json);

            auto events = yuzu::tar::compute_service_diff(previous, current, ts, snap_id);
            if (!events.empty()) {
                db_->insert_events(events);
                total_events += static_cast<int>(events.size());
            }

            db_->set_state("service", services_to_json(current).dump());
        }

        // User diff
        {
            auto current = yuzu::tar::enumerate_users();
            auto prev_json = db_->get_state("user");
            auto previous = json_to_users(prev_json);

            auto events = yuzu::tar::compute_user_diff(previous, current, ts, snap_id);
            if (!events.empty()) {
                db_->insert_events(events);
                total_events += static_cast<int>(events.size());
            }

            db_->set_state("user", users_to_json(current).dump());
        }

        // Periodic purge check (every hour)
        if (ts - last_purge_time_ >= 3600) {
            last_purge_time_ = ts;
            auto retention_str = db_->get_config("retention_days", "7");
            int retention_days = 7;
            try { retention_days = std::stoi(retention_str); } catch (...) {}
            int64_t cutoff = ts - static_cast<int64_t>(retention_days) * 86400;
            int purged = db_->purge(cutoff);
            if (purged > 0) {
                spdlog::info("TAR: purged {} events older than {} days", purged, retention_days);
            }
        }

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

        auto events = db_->query(from, to, type_filter, limit);
        for (const auto& ev : events) {
            ctx.write_output(std::format("{}|{}|{}|{}|{}",
                ev.timestamp, ev.event_type, ev.event_action,
                ev.snapshot_id, ev.detail_json));
        }
        ctx.write_output(std::format("total|{}", events.size()));
        return 0;
    }

    // ── export action (JSON array output) ─────────────────────────────────────

    int do_export(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto from_str = params.get("from", "0");
        auto to_str = params.get("to");
        auto type_filter = std::string{params.get("type")};
        auto limit_str = params.get("limit", "1000");

        int64_t from = 0;
        int64_t to = now_epoch_seconds();
        int limit = 1000;

        try { from = std::stoll(std::string{from_str}); } catch (...) {}
        if (!to_str.empty()) {
            try { to = std::stoll(std::string{to_str}); } catch (...) {}
        }
        try { limit = std::stoi(std::string{limit_str}); } catch (...) {}

        if (limit <= 0 || limit > 10000)
            limit = 1000;

        auto events = db_->query(from, to, type_filter, limit);

        json arr = json::array();
        for (const auto& ev : events) {
            json obj;
            obj["id"] = ev.id;
            obj["timestamp"] = ev.timestamp;
            obj["event_type"] = ev.event_type;
            obj["event_action"] = ev.event_action;
            obj["snapshot_id"] = ev.snapshot_id;
            // Parse detail_json so it's nested JSON, not a string
            try {
                obj["detail"] = json::parse(ev.detail_json);
            } catch (...) {
                obj["detail"] = ev.detail_json;
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

        if (!retention.empty()) {
            int days = 0;
            try { days = std::stoi(std::string{retention}); } catch (...) {}
            if (days >= 1 && days <= 365) {
                db_->set_config("retention_days", std::string{retention});
                ctx.write_output(std::format("config|retention_days|{}", retention));
                changed = true;
            } else {
                ctx.write_output("error|retention_days must be 1-365");
                return 1;
            }
        }

        if (!fast_interval.empty()) {
            try { fast_secs = std::stoi(std::string{fast_interval}); } catch (...) {}
            if (fast_secs >= 10 && fast_secs <= 3600) {
                db_->set_config("fast_interval_seconds", std::string{fast_interval});
                ctx.write_output(std::format("config|fast_interval_seconds|{}", fast_interval));
                changed = true;
            } else {
                ctx.write_output("error|fast_interval must be 10-3600 seconds");
                return 1;
            }
        }

        if (!slow_interval.empty()) {
            try { slow_secs = std::stoi(std::string{slow_interval}); } catch (...) {}
            if (slow_secs >= 30 && slow_secs <= 7200) {
                db_->set_config("slow_interval_seconds", std::string{slow_interval});
                ctx.write_output(std::format("config|slow_interval_seconds|{}", slow_interval));
                changed = true;
            } else {
                ctx.write_output("error|slow_interval must be 30-7200 seconds");
                return 1;
            }
        }

        // Validate fast_interval < slow_interval when both are provided
        if (fast_secs > 0 && slow_secs > 0 && fast_secs >= slow_secs) {
            spdlog::warn("TAR: fast_interval ({}) >= slow_interval ({}); intervals appear inverted",
                         fast_secs, slow_secs);
            ctx.write_output("error|fast_interval must be less than slow_interval");
            return 1;
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

        if (!changed) {
            ctx.write_output("error|no valid configuration parameters provided");
            return 1;
        }

        // Re-register triggers with new intervals if changed
        if (fast_secs > 0 || slow_secs > 0) {
            yuzu::PluginContext pctx{g_ctx_};
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
};

YUZU_PLUGIN_EXPORT(TarPlugin)
