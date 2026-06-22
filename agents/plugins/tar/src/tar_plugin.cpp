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
#include "tar_proc_etw.hpp"
#include "tar_proc_es.hpp"
#include "tar_proc_stream.hpp"
#include "tar_db.hpp"
#include "tar_fleet_snapshot.hpp"
#include "tar_perf.hpp"
#include "tar_proc_perf.hpp"
#include "tar_schema_registry.hpp"
#include "tar_aggregator.hpp"
#include "tar_sql_executor.hpp"

#include <yuzu/agent/network_interfaces.hpp>
#include <yuzu/agent/process_enum.hpp>
#include <yuzu/plugin.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <format>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
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
        arr.push_back({{"pid", p.pid},
                       {"ppid", p.ppid},
                       {"name", p.name},
                       {"cmdline", p.cmdline},
                       {"user", p.user}});
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
        arr.push_back({{"proto", c.proto},
                       {"local_addr", c.local_addr},
                       {"local_port", c.local_port},
                       {"remote_addr", c.remote_addr},
                       {"remote_port", c.remote_port},
                       {"state", c.state},
                       {"pid", c.pid},
                       {"process_name", c.process_name}});
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
        arr.push_back({{"name", s.name},
                       {"display_name", s.display_name},
                       {"status", s.status},
                       {"startup_type", s.startup_type}});
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
        arr.push_back({{"user", u.user},
                       {"domain", u.domain},
                       {"logon_type", u.logon_type},
                       {"session_id", u.session_id}});
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

json software_to_json(const std::vector<yuzu::tar::SoftwareInfo>& apps) {
    json arr = json::array();
    for (const auto& a : apps) {
        arr.push_back({{"name", a.name},
                       {"version", a.version},
                       {"publisher", a.publisher},
                       {"scope", a.scope},
                       {"user", a.user},
                       {"install_date", a.install_date}});
    }
    return arr;
}

std::vector<yuzu::tar::SoftwareInfo> json_to_software(const std::string& s) {
    std::vector<yuzu::tar::SoftwareInfo> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::tar::SoftwareInfo a;
            a.name = j.value("name", "");
            a.version = j.value("version", "");
            a.publisher = j.value("publisher", "");
            a.scope = j.value("scope", "");
            a.user = j.value("user", "");
            a.install_date = j.value("install_date", "");
            result.push_back(std::move(a));
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

// Per-source enable/disable (issue #59). The default for a source with no
// config row yet comes from CaptureSourceDef::default_enabled (true for
// always-on sources, false for opt-in module/procperf/netqual), so a fresh
// agent agrees with tar.status / retention / the paused_at transition.
bool source_enabled(yuzu::tar::TarDatabase& db, std::string_view source) {
    const char* def = yuzu::tar::source_default_enabled(source) ? "true" : "false";
    return db.get_config(std::format("{}_enabled", source), def) != "false";
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
        static const char* acts[] = {"status",         "query",         "snapshot",
                                     "export",         "configure",     "collect_fast",
                                     "collect_slow",   "collect_perf",  "collect_software",
                                     "rollup",         "sql",           "compatibility",
                                     "fleet_snapshot", nullptr};
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
        try {
            fast_interval = std::stoi(fast_str);
        } catch (...) {}
        try {
            slow_interval = std::stoi(slow_str);
        } catch (...) {}

        // Register triggers
        auto fast_config = std::format(
            R"({{"interval_seconds":{},"plugin":"tar","action":"collect_fast","parameters":{{}}}})",
            fast_interval);
        ctx.register_trigger("tar.fast", "interval", fast_config);

        auto slow_config = std::format(
            R"({{"interval_seconds":{},"plugin":"tar","action":"collect_slow","parameters":{{}}}})",
            slow_interval);
        ctx.register_trigger("tar.slow", "interval", slow_config);

        // Perf sampler (BRD A1): 30 s default. perf_interval_seconds = 0
        // disables registration entirely; the per-source perf_enabled config
        // gates collection at run time (both honoured — the trigger seam is
        // the cheap off-switch, the source gate is the operator-facing one).
        int perf_interval = 30;
        try {
            perf_interval = std::stoi(db_->get_config("perf_interval_seconds", "30"));
        } catch (...) {}
        if (perf_interval > 0) {
            auto perf_config = std::format(
                R"({{"interval_seconds":{},"plugin":"tar","action":"collect_perf","parameters":{{}}}})",
                perf_interval);
            ctx.register_trigger("tar.perf", "interval", perf_config);
        }

        // Software install/uninstall sampler: hourly default. Installs are rare
        // and the per-user path mounts NTUSER.DAT hives, so this runs on its own
        // slower trigger rather than the 60s/300s collectors.
        // software_interval_seconds = 0 disables registration entirely; the
        // per-source software_enabled config gates collection at run time.
        int software_interval = 3600;
        try {
            software_interval = std::stoi(db_->get_config("software_interval_seconds", "3600"));
        } catch (...) {}
        if (software_interval > 0) {
            auto software_config = std::format(
                R"({{"interval_seconds":{},"plugin":"tar","action":"collect_software","parameters":{{}}}})",
                software_interval);
            ctx.register_trigger("tar.software", "interval", software_config);
        }

        // Register rollup trigger (15-minute aggregation cycle)
        auto rollup_config = std::format(
            R"({{"interval_seconds":900,"plugin":"tar","action":"rollup","parameters":{{}}}})");
        ctx.register_trigger("tar.rollup", "interval", rollup_config);

        // Gap-free process events: ETW on Windows, Endpoint Security on macOS. On
        // success, collect_fast drains the stream instead of polling; on failure
        // (wrong platform, missing entitlement/privilege, no session) it stays
        // inactive and the poll handles processes (no silent loss). On platforms
        // with no stream the pointer is null and we go straight to the poll.
#ifdef _WIN32
        proc_stream_ = std::make_unique<yuzu::tar::ProcEtwCollector>();
#elif defined(__APPLE__)
        proc_stream_ = std::make_unique<yuzu::tar::ProcEsCollector>();
#endif
        // Boundary for boot backfill: events before this instant came from the
        // pre-session boot window; the live session owns everything from here on.
        const auto t_live = now_epoch_seconds();
        stream_active_ = proc_stream_ && proc_stream_->start();
        if (stream_active_) {
            spdlog::info("TAR: {} process stream active (process poll superseded)",
                         proc_stream_->method_name());

            // Boot-window backfill: replay the AutoLogger .etl (configured at
            // install time WITH a FlushTimer so it's continuously written to
            // disk, and started by the kernel early at boot) for process events
            // with ts < t_live — the window before our live session existed.
            // Read directly from the live file; no session stop / no elevation
            // (the narrow agent account only needs read access).
            //
            // Gated on the `process` source toggle: an operator who disables
            // process collection must not have boot events inserted on the next
            // restart (the AutoLogger is a system-level config the agent can't
            // turn off, but the agent will not STORE what the toggle forbids).
            //
            // Per-boot dedup keyed on the BOOT INSTANT (boot_time_unix), not the
            // earliest event in the .etl: the AutoLogger file is circular, so its
            // earliest event shifts as the buffer wraps — a min-ts key would
            // drift and a late restart would re-insert already-captured events as
            // user-empty rows. The boot instant is stable across same-boot
            // restarts and distinct between boots, so dedup is wrap-immune.
            //
            // Boot events are names-only with NO user: the processes are dead by
            // replay time (no token to query), and the Kernel-Process start event
            // itself carries only SessionID + integrity label, not the owning
            // user. Precise boot-window user attribution would require adding the
            // Security-Auditing 4688 provider to the AutoLogger — deferred.
            if (source_enabled(*db_, "process")) {
                const auto boot_key = std::to_string(yuzu::tar::boot_time_unix());
                if (db_->get_config("last_backfill_boot_ts", "") == boot_key) {
                    spdlog::info("TAR: boot-backfill already done this boot (agent restart) — skipped");
                } else {
                    const auto etl = (std::filesystem::path{db_dir} / "procboot.etl").string();
                    std::error_code ec;
                    if (!std::filesystem::exists(etl, ec)) {
                        // Normal on any install without the boot AutoLogger — e.g.
                        // a minimal install that omits the `advanced` component, or
                        // a fresh install not yet rebooted. Logged, never silent.
                        spdlog::info("TAR: no boot AutoLogger trace at {} — boot-window "
                                     "backfill skipped",
                                     etl);
                    } else {
                        auto boot_evs = yuzu::tar::backfill_proc_events_from_etl(etl, t_live);
                        const auto snap = next_snapshot_id();
                        std::vector<yuzu::tar::ProcessEvent> typed;
                        typed.reserve(boot_evs.size());
                        for (auto& e : boot_evs) {
                            yuzu::tar::ProcessEvent pe;
                            pe.ts = e.ts_unix;
                            pe.snapshot_id = snap;
                            pe.action = e.is_start ? "started" : "stopped";
                            pe.pid = e.pid;
                            pe.ppid = e.ppid;
                            pe.name = e.image_name;
                            pe.user = e.user; // empty for boot-backfill (see above)
                            typed.push_back(std::move(pe));
                        }
                        if (typed.empty()) {
                            spdlog::info("TAR: boot AutoLogger trace had no pre-session process events");
                            db_->set_config("last_backfill_boot_ts", boot_key);
                        } else if (db_->insert_process_events(typed)) {
                            db_->set_config("last_backfill_boot_ts", boot_key);
                            spdlog::info("TAR: boot-backfilled {} process events from the ETW AutoLogger",
                                         typed.size());
                        } else {
                            // Leave the key unset so the next restart retries.
                            spdlog::warn("TAR: boot-backfill insert failed (continuing; "
                                         "will retry on restart)");
                        }
                    }
                }
            } else {
                spdlog::info("TAR: process source disabled — boot-backfill skipped");
            }
        } else {
            spdlog::info("TAR: no gap-free process stream active — using snapshot-diff poll");
        }

        spdlog::info("TAR plugin initialized (fast={}s, slow={}s, db={})", fast_interval,
                     slow_interval, db_path.string());
        return {};
    }

    void shutdown(yuzu::PluginContext& ctx) noexcept override {
        ctx.unregister_trigger("tar.fast");
        ctx.unregister_trigger("tar.slow");
        ctx.unregister_trigger("tar.perf");
        ctx.unregister_trigger("tar.software");
        ctx.unregister_trigger("tar.rollup");
        // Take collect_mu_ around the collector teardown: a collect_fast tick may
        // still be draining proc_stream_ (reads impl_ via drain()/running()), and
        // stop() resets impl_. The host quiesces the trigger engine before
        // shutdown, but the lock makes the ordering safe regardless. The stream's
        // worker (ETW consumer thread / ES handler queue) never takes collect_mu_,
        // so joining it here cannot deadlock.
        {
            std::lock_guard lock(collect_mu_);
            if (proc_stream_) {
                // Windows: closes the ETW session + joins the consumer thread.
                // macOS: es_unsubscribe_all + es_delete_client (blocks until any
                // in-flight handler returns, so no handler touches the ring after).
                proc_stream_->stop();
            }
        }
        db_.reset();
        spdlog::info("TAR plugin shut down");
    }

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (!db_) {
            ctx.write_output("error|TAR database not initialized");
            return 1;
        }

        if (action == "collect_fast")
            return do_collect_fast(ctx);
        if (action == "collect_slow")
            return do_collect_slow(ctx);
        if (action == "collect_perf")
            return do_collect_perf(ctx);
        if (action == "collect_software")
            return do_collect_software(ctx);
        if (action == "status")
            return do_status(ctx);
        if (action == "query")
            return do_query(ctx, params);
        if (action == "export")
            return do_export(ctx, params);
        if (action == "snapshot")
            return do_snapshot(ctx);
        if (action == "configure")
            return do_configure(ctx, params);
        if (action == "rollup")
            return do_rollup(ctx);
        if (action == "sql")
            return do_sql(ctx, params);
        if (action == "compatibility")
            return do_compatibility(ctx);
        if (action == "fleet_snapshot")
            return do_fleet_snapshot(ctx);

        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
    }

private:
    YuzuPluginContext* plugin_ctx_{nullptr};
    std::unique_ptr<yuzu::tar::TarDatabase> db_;
    std::mutex collect_mu_; // Protects the state read-diff-write sequence in collect methods
    yuzu::tar::PerfCounters prev_perf_; // previous perf reading (guarded by collect_mu_)
    yuzu::tar::ProcSnapshot prev_proc_; // previous per-process snapshot (guarded by collect_mu_)

    // Gap-free process start/stop stream: ETW on Windows, Endpoint Security on
    // macOS (one concrete collector per platform behind the ProcStreamCollector
    // interface; null where no stream exists). When it starts, stream_active_ is
    // true and collect_fast DRAINS this instead of polling; if it fails to start
    // (wrong platform, missing entitlement/privilege, session-open failure),
    // stream_active_ stays false and collect_fast falls back to the snapshot-diff
    // poll — so a process source is always present. Drained only under collect_mu_.
    std::unique_ptr<yuzu::tar::ProcStreamCollector> proc_stream_;
    // Atomic: written under collect_mu_ (init + self-heal in collect_fast) but
    // also read WITHOUT the lock by the `status` action (do_status), which runs
    // on a different command thread — a plain bool there would be a data race.
    std::atomic<bool> stream_active_{false};
    // Events drained from the stream ring but not yet persisted because a prior
    // insert failed (DB locked/full); retried on the next collect_fast tick so a
    // transient failure does not lose the batch (UP-2). Guarded by collect_mu_;
    // bounded so a persistently failing DB cannot grow memory without limit.
    std::vector<yuzu::tar::ProcEvent> pending_stream_evs_;
    static constexpr std::size_t kPendingStreamCap = 100000;
    // High-water mark of ProcEventRing::dropped() already logged, so the overflow
    // warning fires on each new drop rather than every tick. Guarded by collect_mu_.
    std::uint64_t last_logged_dropped_{0};

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
        const bool process_enabled = source_enabled(*db_, "process");
        // Forensic-pause contract: the ETW collector owns a live session and keeps
        // filling its ring even while the `process` source is disabled. Unlike the
        // poll (which simply doesn't enumerate), the buffered events SURVIVE — so on
        // the first drain after re-enable they would be persisted into process_live,
        // capturing exactly the paused window the toggle forbids ("the agent will not
        // STORE what the toggle forbids", as already enforced for boot-backfill).
        // Drain-and-DISCARD each disabled tick so nothing from the paused window is
        // ever stored. (Keeps the session warm — no stop/re-arm gap; the kernel
        // session keeps running, events are captured-then-dropped, never inserted.)
        if (stream_active_ && !process_enabled) {
            proc_stream_->drain();       // flush + discard; never inserted
            pending_stream_evs_.clear(); // and drop any pre-disable insert-retry backlog
        }
        if (process_enabled) {
            if (stream_active_) {
                // Gap-free stream (ETW/Windows or Endpoint Security/macOS)
                // supersedes the snapshot-diff poll. Same process_live schema +
                // 'started'/'stopped' so rollups and the $Process_* query surface
                // are unchanged. Names-only (no cmdline — matches the works-council
                // posture); user resolved at drain (SID on Windows, audit-token uid
                // on macOS).
                auto evs = proc_stream_->drain();
                // Prepend events held over from a prior failed insert. The stream
                // has no re-diff self-heal like the poll, so a transient insert
                // failure (DB locked/full) must not silently drop the drained batch
                // (UP-2). Bounded below by kPendingStreamCap.
                if (!pending_stream_evs_.empty()) {
                    evs.insert(evs.begin(), std::make_move_iterator(pending_stream_evs_.begin()),
                               std::make_move_iterator(pending_stream_evs_.end()));
                    pending_stream_evs_.clear();
                }
                std::vector<yuzu::tar::ProcessEvent> typed;
                typed.reserve(evs.size());
                for (auto& e : evs) {
                    // Stabilization exclusions apply here too (parity with the poll).
                    if (!stab_excl.empty() && yuzu::tar::should_redact(e.image_name, stab_excl)) {
                        continue;
                    }
                    yuzu::tar::ProcessEvent pe;
                    pe.ts = e.ts_unix;
                    pe.snapshot_id = snap_id;
                    pe.action = e.is_start ? "started" : "stopped";
                    pe.pid = e.pid;
                    pe.ppid = e.ppid;
                    pe.name = e.image_name;
                    pe.user = e.user;
                    typed.push_back(std::move(pe));
                }
                if (!typed.empty()) {
                    if (!db_->insert_process_events(typed)) {
                        spdlog::error("TAR: process stream insert failed — re-queuing {} events "
                                      "for the next tick",
                                      evs.size());
                        // Retain the drained events (pre-redaction source) and
                        // retry next tick; bound the backlog so a persistently
                        // failing DB cannot grow memory without limit (drops the
                        // oldest, mirroring the ring's overflow posture).
                        pending_stream_evs_ = std::move(evs);
                        if (pending_stream_evs_.size() > kPendingStreamCap) {
                            const auto excess = pending_stream_evs_.size() - kPendingStreamCap;
                            pending_stream_evs_.erase(
                                pending_stream_evs_.begin(),
                                pending_stream_evs_.begin() + static_cast<std::ptrdiff_t>(excess));
                        }
                        ctx.write_output("error|process insert failed");
                        return 1;
                    }
                    total_events += static_cast<int>(typed.size());
                }
                // No state save — the stream is continuous, not a snapshot.

                // Ring-overflow visibility: dropped() is cumulative, so warn only
                // on the delta since the last drain (else it spams every tick for
                // the agent's lifetime after a single burst). Also surfaced via
                // the `status` action (process_stream_dropped).
                if (auto d = proc_stream_->dropped(); d > last_logged_dropped_) {
                    spdlog::warn("TAR: process stream ring overflow — {} dropped (+{} since last drain)",
                                 d, d - last_logged_dropped_);
                    last_logged_dropped_ = d;
                }

                // Self-heal: fall back to the snapshot-diff poll if the stream is no
                // longer delivering, so the process source does not go silently blind
                // (UP-1). Two triggers: running()==false (Windows ETW ProcessTrace
                // returned — another tool stopped it, buffer loss, quota), or
                // stalled()==true (macOS Endpoint Security exposes no liveness API, so
                // a prolonged TOTAL silence is treated as presumed-dead — see
                // ProcEsCollector::stalled and its quiet-host caveat). The batch above
                // is already persisted; `status` then reports
                // process_capture_method=polling.
                if (!proc_stream_->running() || proc_stream_->stalled()) {
                    spdlog::warn("TAR: process stream ended/stalled — falling back to "
                                 "snapshot-diff poll");
                    proc_stream_->stop();
                    stream_active_ = false;
                    // Prime the poll's process baseline with the CURRENT process
                    // set, WITHOUT emitting events. Otherwise the first poll tick
                    // would diff every running process against an empty snapshot
                    // and emit a spurious 'started' for each — double-counting the
                    // processes ETW already recorded as started. Seeding the
                    // baseline here makes the first real diff capture only changes
                    // since the fallback. (Mirrors the poll branch's enumerate +
                    // stabilization-exclusion filter, minus the diff/insert.)
                    auto current = yuzu::agent::enumerate_processes();
                    if (!stab_excl.empty()) {
                        std::erase_if(current, [&](const auto& p) {
                            return yuzu::tar::should_redact(p.name, stab_excl);
                        });
                    }
                    db_->set_state("process", processes_to_json(current).dump());
                }
            } else {
                // No active stream (poll-only platform, or stream unavailable):
                // snapshot-diff poll.
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

                auto typed =
                    yuzu::tar::compute_process_events(previous, current, ts, snap_id, redaction);
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

        // netqual: per-connection TCP quality (BRD Workstream E). OPT-IN,
        // default OFF — per-connection destinations are usage-class telemetry
        // under the works-council posture, so (like procperf) this reads the
        // explicit "true" rather than source_enabled (which defaults a missing
        // key to ENABLED). Co-sampled with the tcp leg above: same snap_id + ts
        // so netqual rows join the connection events on snapshot_id. Only the
        // privacy bucket leaves select_netqual_rows; the raw remote address is
        // dropped there and never persisted. Empty off Linux (collector stub).
        if (db_->get_config("netqual_enabled", "false") == "true") {
            auto samples = yuzu::tar::collect_tcp_quality();
            auto rows = yuzu::tar::select_netqual_rows(samples, ts, snap_id,
                                                       yuzu::tar::kNetQualTopN);
            if (!rows.empty()) {
                // OPT-IN source: a netqual insert failure must NOT fail the whole
                // collect_fast tick — the always-on tcp/process legs already
                // committed, so returning 1 here would misreport a healthy cycle
                // as failed (and suppress the events_recorded line the server
                // reads for retention-pause detection). Log and skip instead.
                if (db_->insert_netqual_samples(rows))
                    total_events += static_cast<int>(rows.size());
                else
                    spdlog::error("TAR: netqual insert failed this tick (skipped)");
            }
        }

        ctx.write_output(std::format("tar|collect_fast|{}|events_recorded", total_events));
        return 0;
    }

    int do_collect_fast(yuzu::CommandContext& ctx) {
        std::lock_guard lock(collect_mu_);
        return collect_fast_impl(ctx);
    }

    // ── collect_perf: device performance sample (BRD A1) ─────────────────────
    // Reads raw kernel counters, derives one perf_live row from the delta vs
    // the previous reading (held in memory — first tick after start is the
    // baseline and records nothing).
    //
    // The counter read (32 PhysicalDrive opens + GetIfTable2) runs OUTSIDE
    // collect_mu_ (gov UP-6): that mutex also serialises collect_fast/slow and
    // fleet_snapshot, so a slow/hung disk IOCTL under the lock would stall them
    // and the /viz hot path. Only the prev_perf_ read-modify-write needs the
    // lock; next_snapshot_id is atomic and insert_perf_sample takes its own.
    //
    // A2: the per-app top-N sampler (tar_proc_perf) rides the SAME tick under
    // its OWN `procperf` source toggle — disabling device perf does not kill
    // per-app sampling or vice versa (both die when the tar.perf trigger is
    // unregistered via perf_interval_seconds=0).
    int do_collect_perf(yuzu::CommandContext& ctx) {
        int rc = 0;
        if (!source_enabled(*db_, "perf")) {
            ctx.write_output("tar|collect_perf|0|source_disabled");
        } else {
            const auto cur = yuzu::tar::read_perf_counters(); // syscalls, no lock held
            if (!cur.valid) {
                ctx.write_output("tar|collect_perf|0|unsupported_platform");
            } else {
                yuzu::tar::PerfSample sample;
                {
                    std::lock_guard lock(collect_mu_); // prev_perf_ read-modify-write only
                    sample = yuzu::tar::derive_sample(prev_perf_, cur);
                    prev_perf_ = cur;
                }
                if (!sample.valid) {
                    ctx.write_output("tar|collect_perf|0|baseline");
                } else {
                    yuzu::tar::PerfRow row;
                    row.ts = cur.ts_epoch;
                    row.snapshot_id = next_snapshot_id();
                    row.cpu_pct = sample.cpu_pct;
                    row.mem_used_pct = sample.mem_used_pct;
                    row.commit_pct = sample.commit_pct;
                    row.disk_read_bps = sample.disk_read_bps;
                    row.disk_write_bps = sample.disk_write_bps;
                    row.disk_read_lat_us = sample.disk_read_lat_us;
                    row.disk_write_lat_us = sample.disk_write_lat_us;
                    row.net_rx_bps = sample.net_rx_bps;
                    row.net_tx_bps = sample.net_tx_bps;
                    if (!db_->insert_perf_sample(row)) {
                        ctx.write_output("error|perf insert failed");
                        rc = 1;
                    } else {
                        ctx.write_output("tar|collect_perf|1|sample_recorded");
                    }
                }
            }
        }

        // A2 per-app leg (independent of the device leg's outcome). Unlike the
        // other TAR sources, procperf defaults OFF (opt-in): per-application
        // CPU/working-set reveals which applications run on a device, which is
        // usage-class telemetry under the works-council posture (W0 commits
        // app_usage-class collectors to default-off pending per-category
        // toggles + DPO concurrence) — distinct from device-level perf, which
        // carries no per-app identity and stays default-on. So this gate reads
        // the explicit "true" rather than going through source_enabled (which
        // defaults missing keys to enabled). See docs/dex-brd-coverage.md and
        // memory project-telemetry-privacy-works-council.
        if (db_->get_config("procperf_enabled", "false") != "true") {
            ctx.write_output("tar|collect_procperf|0|source_disabled");
            return rc;
        }
        auto proc_cur = yuzu::tar::read_proc_counters(); // one snapshot, no lock held
        if (!proc_cur.valid) {
            ctx.write_output("tar|collect_procperf|0|unsupported_platform");
            return rc;
        }
        const auto ts = proc_cur.ts_epoch; // before the move; never read prev_proc_ unlocked
        const auto redaction = load_redaction_patterns(*db_);
        std::vector<yuzu::tar::ProcPerfSample> samples;
        {
            std::lock_guard lock(collect_mu_); // prev_proc_ read-modify-write only
            samples = yuzu::tar::derive_proc_samples(prev_proc_, proc_cur, redaction);
            prev_proc_ = std::move(proc_cur);
        }
        if (samples.empty()) {
            ctx.write_output("tar|collect_procperf|0|baseline");
            return rc;
        }
        const auto snap_id = next_snapshot_id();
        std::vector<yuzu::tar::ProcPerfRow> rows;
        rows.reserve(samples.size());
        for (auto& s : samples) {
            yuzu::tar::ProcPerfRow r;
            r.ts = ts;
            r.snapshot_id = snap_id;
            r.name = std::move(s.name);
            r.instances = s.instances;
            r.cpu_pct = s.cpu_pct;
            r.ws_bytes = s.ws_bytes;
            rows.push_back(std::move(r));
        }
        if (!db_->insert_proc_perf_samples(rows)) {
            ctx.write_output("error|procperf insert failed");
            return 1;
        }
        ctx.write_output(std::format("tar|collect_procperf|{}|apps_recorded", rows.size()));
        return rc;
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

    // ── collect_software: installed-software inventory diff ───────────────────
    // Diffs the installed-software inventory and records install/remove/upgrade
    // events. Runs on the dedicated tar.software trigger (hourly default).
    //
    // The enumeration — which on Windows walks the registry and mounts NTUSER.DAT
    // hives for logged-off profiles — runs OUTSIDE collect_mu_ so a slow registry
    // pass cannot stall collect_fast/slow/fleet_snapshot under that shared lock
    // (gov UP-6, mirrors collect_perf). Only the state read-diff-write is locked.
    //
    // Cold start: the FIRST run on a host (no prior "software" state) seeds the
    // baseline WITHOUT emitting events — an 'installed' event must mean "installed
    // now", not "already present when the agent started watching". This is a
    // deliberate divergence from the service/user cold-start burst and mirrors the
    // process-stream fallback baseline seed.
    int do_collect_software(yuzu::CommandContext& ctx) {
        if (!source_enabled(*db_, "software")) {
            ctx.write_output("tar|collect_software|0|source_disabled");
            return 0;
        }

        // Enumerate outside the lock (registry walk + possible hive mounts).
        auto current = yuzu::tar::enumerate_software();
        const auto ts = now_epoch_seconds();
        const auto snap_id = next_snapshot_id();

        std::lock_guard lock(collect_mu_);
        auto prev_json = db_->get_state("software");
        if (prev_json.empty()) {
            // Cold start: seed the baseline silently, emit nothing. (get_state
            // returns "" only when no row exists; after this it is at least "[]".)
            db_->set_state("software", software_to_json(current).dump());
            ctx.write_output("tar|collect_software|0|baseline_seeded");
            return 0;
        }

        auto previous = json_to_software(prev_json);
        auto typed = yuzu::tar::compute_software_events(previous, current, ts, snap_id);
        if (!typed.empty()) {
            if (!db_->insert_software_events(typed)) {
                spdlog::error("TAR: failed to insert software events, skipping state save");
                ctx.write_output("error|software insert failed");
                return 1;
            }
        }
        db_->set_state("software", software_to_json(current).dump());
        ctx.write_output(std::format("tar|collect_software|{}|events_recorded", typed.size()));
        return 0;
    }

    // ── status action ─────────────────────────────────────────────────────────

    int do_status(yuzu::CommandContext& ctx) {
        auto s = db_->stats();
        ctx.write_output(std::format("record_count|{}", s.record_count));
        ctx.write_output(std::format("oldest_timestamp|{}", s.oldest_timestamp));
        ctx.write_output(std::format("newest_timestamp|{}", s.newest_timestamp));
        ctx.write_output(std::format("db_size_bytes|{}", s.db_size_bytes));
        ctx.write_output(std::format("retention_days|{}", s.retention_days));

        // Per-source enable/disable state (issue #59) plus the operational
        // surface PR-A (#547) needs: paused_at, live_rows, oldest_ts. Default
        // = enabled, paused_at = 0, so operators that never call `configure`
        // see the steady-state behavior. live_rows / oldest_ts are queried
        // from the per-source `*_live` table; an empty table reports 0 / 0.
        for (const auto& src : yuzu::tar::capture_sources()) {
            std::string enabled_key = std::format("{}_enabled", src.name);
            // Default to the source's declared default (false for opt-in
            // module/procperf/netqual) so a fresh agent does not misreport an
            // opt-in source as enabled.
            auto enabled_val =
                db_->get_config(enabled_key, src.default_enabled ? "true" : "false");
            ctx.write_output(std::format("config|{}|{}", enabled_key, enabled_val));

            std::string paused_at_key = std::format("{}_paused_at", src.name);
            auto paused_at_val = db_->get_config(paused_at_key, "0");
            ctx.write_output(std::format("config|{}|{}", paused_at_key, paused_at_val));

            std::string live_table = std::format("{}_live", src.name);
            auto count_q = db_->execute_query("SELECT COUNT(*) FROM " + live_table, /*max_rows=*/1);
            int64_t live_rows = 0;
            if (count_q.has_value() && !count_q->rows.empty()) {
                try {
                    live_rows = std::stoll(count_q->rows[0][0]);
                } catch (...) {}
            }
            ctx.write_output(std::format("config|{}_live_rows|{}", src.name, live_rows));

            // `ts` is the column name on every `*_live` table per the schema
            // registry. NULL on empty table → 0 fallback.
            auto oldest_q =
                db_->execute_query("SELECT IFNULL(MIN(ts), 0) FROM " + live_table, /*max_rows=*/1);
            int64_t oldest_ts = 0;
            if (oldest_q.has_value() && !oldest_q->rows.empty()) {
                try {
                    oldest_ts = std::stoll(oldest_q->rows[0][0]);
                } catch (...) {}
            }
            ctx.write_output(std::format("config|{}_oldest_ts|{}", src.name, oldest_ts));
        }
        // Currently-configured network capture method (defaults to "polling").
        auto net_method = db_->get_config("network_capture_method", "polling");
        ctx.write_output(std::format("config|network_capture_method|{}", net_method));

        // Process stream health. capture_method reflects the LIVE path: the
        // stream's method_name() ("etw" on Windows, "endpoint_security" on macOS)
        // while the stream runs, "polling" if it never started or self-healed to
        // the poll after a session death. dropped is the cumulative ring-overflow
        // count (NFR visibility — there is no agent /metrics endpoint; this action
        // is the operator/agentic surface).
        ctx.write_output(std::format("config|process_capture_method|{}",
                                     (stream_active_ && proc_stream_) ? proc_stream_->method_name()
                                                                      : "polling"));
        // dropped() reads the ring's own atomic (independent of the session
        // lifecycle) so it is safe without collect_mu_. Emit unconditionally — 0 on
        // a poll-only platform (null proc_stream_) — so the key is always present and
        // agentic consumers can read it without a presence check.
        //
        // process_stream_dropped is the USERSPACE ring-overflow count (events the
        // drain tick could not keep up with). process_stream_kernel_dropped is the
        // distinct kernel/provider-side drop count (Endpoint Security seq_num gaps;
        // 0 on ETW, which exposes no per-message sequence to inspect here).
        ctx.write_output(std::format("config|process_stream_dropped|{}",
                                     proc_stream_ ? proc_stream_->dropped() : 0));
        ctx.write_output(std::format("config|process_stream_kernel_dropped|{}",
                                     proc_stream_ ? proc_stream_->kernel_dropped() : 0));
        return 0;
    }

    // ── compatibility action (issue #59) ──────────────────────────────────────
    //
    // Emits one row per (source, OS) describing how the source captures data
    // on that platform and any known constraint. Pipe-delimited so the
    // existing dashboard renderer can show it as a table without a JSON
    // codec change.
    int do_compatibility(yuzu::CommandContext& ctx) {
        ctx.write_output("header|source|os|status|capture_method|notes");
        for (const auto& src : yuzu::tar::capture_sources()) {
            for (const auto& os : src.os_support) {
                std::string_view status_str;
                switch (os.status) {
                case yuzu::tar::OsSupportStatus::kSupported:
                    status_str = "supported";
                    break;
                case yuzu::tar::OsSupportStatus::kSupportedConstrained:
                    status_str = "constrained";
                    break;
                case yuzu::tar::OsSupportStatus::kPlanned:
                    status_str = "planned";
                    break;
                case yuzu::tar::OsSupportStatus::kUnsupported:
                    status_str = "unsupported";
                    break;
                }
                ctx.write_output(std::format("row|{}|{}|{}|{}|{}", src.name, os.os, status_str,
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

        try {
            from = std::stoll(std::string{from_str});
        } catch (...) {
            ctx.write_output("error|invalid 'from' parameter (must be epoch seconds)");
            return 1;
        }
        if (!to_str.empty()) {
            try {
                to = std::stoll(std::string{to_str});
            } catch (...) {
                ctx.write_output("error|invalid 'to' parameter (must be epoch seconds)");
                return 1;
            }
        }
        try {
            limit = std::stoi(std::string{limit_str});
        } catch (...) {}

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
                  "'' AS detail_json FROM process_live" +
                  where + tail;
        } else if (type_filter == "network") {
            sql = "SELECT ts, 'network' AS event_type, action, snapshot_id, "
                  "'' AS detail_json FROM tcp_live" +
                  where + tail;
        } else if (type_filter == "service") {
            sql = "SELECT ts, 'service' AS event_type, action, snapshot_id, "
                  "'' AS detail_json FROM service_live" +
                  where + tail;
        } else if (type_filter == "user") {
            sql = "SELECT ts, 'user' AS event_type, action, snapshot_id, "
                  "'' AS detail_json FROM user_live" +
                  where + tail;
        } else {
            sql = "SELECT * FROM ("
                  "SELECT ts, 'process' AS event_type, action, snapshot_id, '' AS detail_json FROM "
                  "process_live" +
                  where +
                  " UNION ALL "
                  "SELECT ts, 'network', action, snapshot_id, '' FROM tcp_live" +
                  where +
                  " UNION ALL "
                  "SELECT ts, 'service', action, snapshot_id, '' FROM service_live" +
                  where +
                  " UNION ALL "
                  "SELECT ts, 'user', action, snapshot_id, '' FROM user_live" +
                  where + ")" + tail;
        }

        auto query_result = db_->execute_query(sql);
        if (!query_result) {
            ctx.write_output(std::format("error|{}", query_result.error()));
            return 1;
        }
        for (const auto& row : query_result->rows) {
            std::string line;
            for (size_t i = 0; i < row.size(); ++i) {
                if (i > 0)
                    line += '|';
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

        try {
            from = std::stoll(std::string{from_str});
        } catch (...) {}
        if (!to_str.empty()) {
            try {
                to = std::stoll(std::string{to_str});
            } catch (...) {}
        }
        try {
            limit = std::stoi(std::string{limit_str});
        } catch (...) {}
        if (limit <= 0 || limit > 10000)
            limit = 1000;

        // Pick the right live table (HP-5: handle empty filter and unknown types)
        //
        // For the "no filter" case we have to UNION ALL four tables that do
        // not share a column count or schema. Project each branch to a
        // uniform shape (source, ts, snapshot_id, action, summary) so the
        // UNION is well-typed and the JSON envelope stays consistent for
        // SIEM ingest. Callers that want per-table fields should pass a
        // type filter.
        std::string sql;
        if (type_filter.empty()) {
            sql = std::format("SELECT * FROM ("
                              "SELECT 'process' AS source, ts, snapshot_id, action, "
                              "       (name || '[' || pid || ']') AS summary "
                              "  FROM process_live WHERE ts >= {} AND ts <= {} UNION ALL "
                              "SELECT 'network', ts, snapshot_id, action, "
                              "       (proto || ' ' || local_addr || ':' || local_port) AS summary "
                              "  FROM tcp_live WHERE ts >= {} AND ts <= {} UNION ALL "
                              "SELECT 'service', ts, snapshot_id, action, "
                              "       (name || ' (' || status || ')') AS summary "
                              "  FROM service_live WHERE ts >= {} AND ts <= {} UNION ALL "
                              "SELECT 'user', ts, snapshot_id, action, "
                              "       (user || '@' || COALESCE(domain,'')) AS summary "
                              "  FROM user_live WHERE ts >= {} AND ts <= {}"
                              ") ORDER BY ts ASC LIMIT {}",
                              from, to, from, to, from, to, from, to, limit);
        } else {
            std::string table;
            if (type_filter == "process")
                table = "process_live";
            else if (type_filter == "network")
                table = "tcp_live";
            else if (type_filter == "service")
                table = "service_live";
            else if (type_filter == "user")
                table = "user_live";
            else {
                ctx.write_output(std::format("error|unknown type filter: {}", type_filter));
                return 1;
            }
            sql =
                std::format("SELECT * FROM {} WHERE ts >= {} AND ts <= {} ORDER BY ts ASC LIMIT {}",
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

    // ── fleet_snapshot action (single JSON document for fleet-topology viz) ──
    //
    // Re-enumerates processes + connections + local IPs on demand and emits a
    // single JSON line conforming to fleet_snapshot.v1. Used by the server-side
    // FleetTopologyStore on cache miss to assemble the /viz/fleet topology.
    //
    // Locking: takes collect_mu_ to serialise OS-resource enumeration with the
    // collect_fast / collect_slow paths. The action does not write to tar.db,
    // but enumerate_processes() / enumerate_connections() open many fds and a
    // concurrent collect_fast cycle would double the OS pressure (governance
    // round 1, plugin-B2 + UP-1).
    //
    // Source gating: if the operator paused process or tcp capture (forensic
    // hold, PII compliance regime), fleet_snapshot must respect that decision
    // -- otherwise a paused source silently leaks data through the new path
    // (governance round 1, plugin-B1 + compliance-F1). When a source is
    // disabled, the corresponding list is emitted empty with truncated_*=false
    // and the snapshot carries `source_paused.process` / `.tcp` markers.
    //
    // Redaction: kDefaultRedactionPatterns is unioned with the operator-loaded
    // patterns so an empty config does NOT disable redaction
    // (governance round 1, sec-M1 + compliance-F3).
    int do_fleet_snapshot(yuzu::CommandContext& ctx) {
        std::lock_guard lock(collect_mu_);
        auto ts = now_epoch_seconds();
        auto hostname = yuzu::agent::get_hostname();
        auto local_ips = yuzu::agent::enumerate_local_ips();

        const bool process_on = source_enabled(*db_, "process");
        const bool tcp_on = source_enabled(*db_, "tcp");

        std::vector<yuzu::agent::ProcessInfo> processes;
        if (process_on) {
            processes = yuzu::agent::enumerate_processes();
        }
        std::vector<yuzu::tar::NetConnection> connections;
        if (tcp_on) {
            auto live = yuzu::tar::enumerate_connections();
            // Widen the snapshot from "currently ESTABLISHED" to "ESTABLISHED
            // within the rolling window" by joining /proc with TAR's tcp_live
            // warehouse. A connection that closed 30 minutes ago still
            // appears with last_seen_seconds_ago>0 so the viz can render it
            // as a tube. Window default 3600s; operator-tunable via the
            // fleet_snapshot_window_seconds config (added by tar.configure).
            int window_seconds = 3600;
            if (auto cfg = db_->get_config("fleet_snapshot_window_seconds", ""); !cfg.empty()) {
                try {
                    window_seconds = std::max(0, std::stoi(cfg));
                } catch (...) {
                    // Bad config value — fall back to the default rather
                    // than fail the whole snapshot.
                }
            }
            std::vector<yuzu::tar::NetworkEvent> recent;
            if (window_seconds > 0) {
                auto q = db_->query_recent_tcp_connections(ts - window_seconds);
                if (q.has_value()) {
                    recent = std::move(*q);
                } else {
                    spdlog::warn("tar.fleet_snapshot: tcp_live query failed: {}", q.error());
                }
            }
            connections = yuzu::tar::merge_live_and_recent_connections(live, recent, ts);
        }

        // Defence-in-depth: union operator patterns with the compiled-in
        // defaults so an empty/missing config still applies *password*, *secret*,
        // *token*, *api_key*, *credential*. The `should_redact` matcher returns
        // true on the first hit, so duplicates are harmless.
        auto redaction = load_redaction_patterns(*db_);
        for (const auto& def : yuzu::tar::kDefaultRedactionPatterns) {
            if (std::find(redaction.begin(), redaction.end(), def) == redaction.end())
                redaction.push_back(def);
        }

        spdlog::info("tar.fleet_snapshot host={} procs={} conns={} ips={} "
                     "process_on={} tcp_on={}",
                     hostname, processes.size(), connections.size(), local_ips.size(), process_on,
                     tcp_on);

        auto payload = yuzu::tar::build_fleet_snapshot_json(
            processes, connections, local_ips, hostname, ts, redaction, process_on, tcp_on);

        ctx.write_output(payload);
        return 0;
    }

    // ── configure action ──────────────────────────────────────────────────────

    int do_configure(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto retention = params.get("retention_days");
        auto fast_interval = params.get("fast_interval");
        auto slow_interval = params.get("slow_interval");
        auto software_interval = params.get("software_interval");
        auto redaction = params.get("redaction_patterns");

        bool changed = false;
        int fast_secs = 0;
        int slow_secs = 0;
        int days = 0;
        // Software interval accepts 0 (disable the trigger) or 300–86400, so it
        // needs a "was it provided" flag distinct from the 0 sentinel.
        int software_secs = 0;
        bool software_provided = false;

        // M13: Validate ALL parameters BEFORE writing any to the database
        if (!retention.empty()) {
            try {
                days = std::stoi(std::string{retention});
            } catch (...) {}
            if (days < 1 || days > 365) {
                ctx.write_output("error|retention_days must be 1-365");
                return 1;
            }
        }

        if (!fast_interval.empty()) {
            try {
                fast_secs = std::stoi(std::string{fast_interval});
            } catch (...) {}
            if (fast_secs < 10 || fast_secs > 3600) {
                ctx.write_output("error|fast_interval must be 10-3600 seconds");
                return 1;
            }
        }

        if (!slow_interval.empty()) {
            try {
                slow_secs = std::stoi(std::string{slow_interval});
            } catch (...) {}
            if (slow_secs < 30 || slow_secs > 7200) {
                ctx.write_output("error|slow_interval must be 30-7200 seconds");
                return 1;
            }
        }

        if (!software_interval.empty()) {
            software_provided = true;
            bool parsed = false;
            try {
                software_secs = std::stoi(std::string{software_interval});
                parsed = true;
            } catch (...) {}
            // 0 disables the trigger; otherwise 300–86400 (5 min – 1 day). A
            // non-numeric value is rejected rather than silently treated as 0.
            if (!parsed || software_secs < 0 ||
                (software_secs > 0 && (software_secs < 300 || software_secs > 86400))) {
                ctx.write_output("error|software_interval must be 0 (disable) or 300-86400 seconds");
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

        if (software_provided) {
            db_->set_config("software_interval_seconds", std::to_string(software_secs));
            ctx.write_output(std::format("config|software_interval_seconds|{}", software_secs));
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
                        ctx.write_output(
                            "error|redaction_patterns must contain only non-empty strings");
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
        //
        // PR-A: when a transition enable→disable happens, record the wall-clock
        // timestamp in `<source>_paused_at` so the server-side retention-paused
        // dashboard list (#547) can render "paused since" without inferring it
        // from the audit log. The reverse transition clears the value to "0"
        // (we do not delete keys — a missing key would be ambiguous with "never
        // paused"). The timestamp is operator-facing wall-clock seconds; clock
        // skew is acceptable because the surface is "paused since approximately
        // X" and the ground truth is the agent's view.
        for (const auto& src : yuzu::tar::capture_sources()) {
            std::string key = std::format("{}_enabled", src.name);
            auto val = params.get(key);
            if (val.empty())
                continue;
            std::string v{val};
            if (v != "true" && v != "false") {
                ctx.write_output(std::format("error|{} must be 'true' or 'false'", key));
                return 1;
            }
            yuzu::tar::apply_source_enabled_transition(*db_, src.name, v, now_epoch_seconds());
            ctx.write_output(std::format("config|{}|{}", key, v));
            // Echo the resulting paused_at so the operator/dashboard sees the
            // transition timestamp without an extra status round-trip. We
            // re-read it post-write rather than re-deriving the transition
            // here — single source of truth.
            std::string paused_at_key = std::format("{}_paused_at", src.name);
            ctx.write_output(
                std::format("config|{}|{}", paused_at_key, db_->get_config(paused_at_key, "0")));
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
                ctx.write_output(
                    std::format("warn|network_capture_method '{}' accepted but not yet "
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
                    ctx.write_output("error|process_stabilization_exclusions must be a JSON array");
                    return 1;
                }
                for (const auto& elem : arr) {
                    if (!elem.is_string() || elem.get<std::string>().empty()) {
                        ctx.write_output("error|process_stabilization_exclusions must contain only "
                                         "non-empty strings");
                        return 1;
                    }
                }
                db_->set_config("process_stabilization_exclusions", std::string{exc});
                ctx.write_output(std::format("config|process_stabilization_exclusions|{}", exc));
                changed = true;
            } catch (...) {
                ctx.write_output("error|process_stabilization_exclusions must be valid JSON array");
                return 1;
            }
        }

        if (!changed) {
            ctx.write_output("error|no valid configuration parameters provided");
            return 1;
        }

        // Re-register triggers with new intervals if changed
        if (fast_secs > 0 || slow_secs > 0 || software_provided) {
            yuzu::PluginContext pctx{plugin_ctx_};
            if (fast_secs > 0) {
                pctx.unregister_trigger("tar.fast");
                auto cfg = std::format(
                    R"({{"interval_seconds":{},"plugin":"tar","action":"collect_fast"}})",
                    fast_secs);
                pctx.register_trigger("tar.fast", "interval", cfg);
                ctx.write_output(std::format("trigger|tar.fast|re-registered|{}s", fast_secs));
            }
            if (slow_secs > 0) {
                pctx.unregister_trigger("tar.slow");
                auto cfg = std::format(
                    R"({{"interval_seconds":{},"plugin":"tar","action":"collect_slow"}})",
                    slow_secs);
                pctx.register_trigger("tar.slow", "interval", cfg);
                ctx.write_output(std::format("trigger|tar.slow|re-registered|{}s", slow_secs));
            }
            if (software_provided) {
                // Always unregister first; re-register only when non-zero. An
                // interval of 0 leaves the trigger absent (collection disabled
                // until re-registered with a positive interval or agent restart).
                pctx.unregister_trigger("tar.software");
                if (software_secs > 0) {
                    auto cfg = std::format(
                        R"({{"interval_seconds":{},"plugin":"tar","action":"collect_software"}})",
                        software_secs);
                    pctx.register_trigger("tar.software", "interval", cfg);
                    ctx.write_output(
                        std::format("trigger|tar.software|re-registered|{}s", software_secs));
                } else {
                    ctx.write_output("trigger|tar.software|unregistered|0s");
                }
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

        auto query_result = db_->execute_user_query(*validated);
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
                if (i > 0)
                    line += '|';
                line += row[i];
            }
            ctx.write_output(line);
        }

        ctx.write_output(std::format("__total__|{}", result.rows.size()));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(TarPlugin)
