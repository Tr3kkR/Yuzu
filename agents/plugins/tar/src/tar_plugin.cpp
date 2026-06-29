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
#include "tar_module_etw.hpp"
#include "tar_db.hpp"
#include "tar_fleet_snapshot.hpp"
#include "tar_perf.hpp"
#include "tar_proc_perf.hpp"
#include "tar_schema_registry.hpp"
#include "tar_aggregator.hpp"
#include "tar_software_core.hpp"
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
#include <unordered_map>
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

json arp_to_json(const std::vector<yuzu::tar::ArpEntry>& entries) {
    json arr = json::array();
    for (const auto& e : entries) {
        arr.push_back({{"interface", e.iface},
                       {"ip_address", e.ip_address},
                       {"mac_address", e.mac_address},
                       {"entry_type", e.entry_type}});
    }
    return arr;
}

std::vector<yuzu::tar::ArpEntry> json_to_arp(const std::string& s) {
    std::vector<yuzu::tar::ArpEntry> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::tar::ArpEntry e;
            e.iface = j.value("interface", "");
            e.ip_address = j.value("ip_address", "");
            e.mac_address = j.value("mac_address", "");
            e.entry_type = j.value("entry_type", "");
            result.push_back(std::move(e));
        }
    } catch (...) {}
    return result;
}

json dns_to_json(const std::vector<yuzu::tar::DnsEntry>& entries) {
    json arr = json::array();
    for (const auto& e : entries) {
        arr.push_back({{"name", e.name},
                       {"record_type", e.record_type},
                       {"data", e.data},
                       {"ttl_remaining_s", e.ttl_remaining_s},
                       {"source", e.source}});
    }
    return arr;
}

std::vector<yuzu::tar::DnsEntry> json_to_dns(const std::string& s) {
    std::vector<yuzu::tar::DnsEntry> result;
    if (s.empty())
        return result;
    try {
        auto arr = json::parse(s);
        for (const auto& j : arr) {
            yuzu::tar::DnsEntry e;
            e.name = j.value("name", "");
            e.record_type = j.value("record_type", "");
            e.data = j.value("data", "");
            e.ttl_remaining_s = j.value("ttl_remaining_s", int64_t{0});
            e.source = j.value("source", "");
            result.push_back(std::move(e));
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

// Installed-software state (de)serialisation lives in tar_software_core.cpp
// (software_state_to_json / software_state_from_json) so the orchestration that
// uses it — software_collect_core — is unit-testable off-Windows.

// ── Redaction pattern loading ────────────────────────────────────────────────

std::vector<std::string> load_redaction_patterns(yuzu::tar::TarDatabase& db) {
    // The built-in patterns (`kDefaultRedactionPatterns` — password/secret/token/
    // api_key/credential) are the baseline content-protection layer for
    // process_live, and they MUST always apply: an operator can ADD patterns via
    // configure but can never fully DISABLE redaction. So union the defaults into
    // whatever is stored — fail-closed (fjarvis HIGH). A bare `parse_pattern_config`
    // fallback was fail-OPEN: it returns the safe built-in set only for an empty or
    // non-array value, but a *valid array whose elements all get dropped* (`[]`,
    // `[1,2,3]`, all-over-long, or `["*"]` whose stripped core is empty) returns an
    // EMPTY vector — silently disabling redaction so `password`/`token`/`secret`
    // land in process_live in plaintext. collect_fast and procperf called this
    // without the union do_fleet_snapshot already applied; centralising it here
    // closes all three paths at once and removes the divergent local default list.
    // #541 — parse_pattern_config still bounds + sanitises at load (drops
    // non-string/empty/over-long, truncates to the element cap), because this runs
    // every fast-collect cycle on whatever is stored. ensure_redaction_defaults
    // then unions the built-ins — the single, unit-tested home of the fail-closed
    // guarantee, shared with do_fleet_snapshot.
    std::vector<std::string> result;
    if (auto v = yuzu::tar::parse_pattern_config(db.get_config("redaction_patterns")))
        result = std::move(*v);
    return yuzu::tar::ensure_redaction_defaults(std::move(result));
}

// Per-source enable/disable (issue #59). The default for a source with no
// config row yet comes from CaptureSourceDef::default_enabled (true for
// always-on sources, false for opt-in module/procperf/netqual), so a fresh
// agent agrees with tar.status / retention / the paused_at transition.
//
// #560 — gate on the canonical tri-state, not `!= "false"`. A value the plugin
// never writes ("maybe", "1", "", a bit-flip) maps to "errored", which is NOT
// "true", so collection STOPS (fail closed). The bare `!= "false"` treated every
// such value as enabled, so a source an operator paused for forensics whose
// `_enabled` value was corrupted or tampered kept collecting — and disagreed
// with the tri-state `status` reports. run_retention() shares the same canonical
// gate so an "errored" source's rows are preserved, not pruned.
bool source_enabled(yuzu::tar::TarDatabase& db, std::string_view source) {
    const char* def = yuzu::tar::source_default_enabled(source) ? "true" : "false";
    return yuzu::tar::canonical_source_enabled(
               db.get_config(std::format("{}_enabled", source), def)) == "true";
}

// Process stabilization exclusion patterns (issue #59). Empty = no exclusions.
std::vector<std::string> load_stabilization_exclusions(yuzu::tar::TarDatabase& db) {
    auto stored = db.get_config("process_stabilization_exclusions");
    if (stored.empty())
        return {};
    // #541 — bound + sanitise at load (see load_redaction_patterns), AND enforce
    // the ≥3-char effective-core floor here (require_min_core_len=true): unlike
    // redaction, a sub-floor exclusion like ["a"] or ["*a*"] silently drops every
    // process whose name contains that core, so a value persisted before the
    // floor existed (no-tamper upgrade) or tampered out of band must be filtered
    // on this hot path, not just rejected at configure. A non-array stored value
    // yields no exclusions (the safe default — nothing dropped).
    if (auto v = yuzu::tar::parse_pattern_config(stored, /*require_min_core_len=*/true))
        return std::move(*v);
    return {};
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

        // Software install/uninstall sampler: hourly default. Installs are rare,
        // so this runs on its own slower trigger rather than the 60s/300s collectors.
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
                    spdlog::info(
                        "TAR: boot-backfill already done this boot (agent restart) — skipped");
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
                            spdlog::info(
                                "TAR: boot AutoLogger trace had no pre-session process events");
                            db_->set_config("last_backfill_boot_ts", boot_key);
                        } else if (db_->insert_process_events(typed)) {
                            db_->set_config("last_backfill_boot_ts", boot_key);
                            spdlog::info(
                                "TAR: boot-backfilled {} process events from the ETW AutoLogger",
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

        // M2: seed the opt-in module_enabled key so the configure / retention /
        // retention-paused-list machinery (which default a MISSING key to ENABLED
        // via source_enabled) agrees with the collector's explicit default-off.
        if (db_->get_config("module_enabled", "").empty()) {
            db_->set_config("module_enabled", "false");
        }
        // #1620: seed the opt-in software_enabled key (the `software` source is
        // default-off, like module) so the configure / retention /
        // retention-paused-list machinery (which default a MISSING key to ENABLED
        // via source_enabled) agrees with the collector's explicit default-off.
        if (db_->get_config("software_enabled", "").empty()) {
            db_->set_config("software_enabled", "false");
        }
#ifdef _WIN32
        // Construct the Windows ETW image-load collector; the session is STARTED
        // LAZILY by collect_fast on the first tick where module_enabled is true (so
        // enabling takes effect on the next tick — no restart — matching
        // procperf/netqual, and a transient session death auto-re-arms). Null on
        // non-Windows (M4/M5 add macOS Endpoint Security, M6 adds Linux auditd).
        module_stream_ = std::make_unique<yuzu::tar::ModuleEtwCollector>();
#endif

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
            if (module_stream_) {
                // Windows: closes the module-load ETW session + joins its
                // consumer thread (idempotent; safe if never started).
                module_stream_->stop();
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
    // Separate mutex for the software source: its state read-diff-write touches
    // only the "software" KV state (never prev_perf_/prev_proc_/proc_stream_), and
    // the registry walk + JSON (de)serialise can be slow on many-profile hosts —
    // putting it on collect_mu_ would stall collect_fast/slow/fleet_snapshot. A
    // dedicated mutex serialises concurrent collect_software (manual vs trigger)
    // without that cross-collector coupling.
    std::mutex software_collect_mu_;
    yuzu::tar::PerfCounters prev_perf_; // previous perf reading (guarded by collect_mu_)
    yuzu::tar::ProcSnapshot prev_proc_; // previous per-process snapshot (guarded by collect_mu_)
    // Per-app version cache, keyed by (pid, create_time): resolves each top-N
    // process once while it stays in the set (read-once-near-launch). Touched
    // only by resolve_proc_versions OUTSIDE collect_mu_ — so it has its own
    // mutex; never hold collect_mu_ across the OpenProcess/file-read it drives.
    std::mutex proc_ver_mu_;
    std::unordered_map<std::uint64_t, std::string> version_cache_;

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

    // ── M2: gap-free module/image-load stream (Windows ETW; null elsewhere) ───
    // Unlike the always-on process stream, this is OPT-IN (module_enabled,
    // default off) and high-volume, so the session is started LAZILY by
    // collect_fast on the first tick where module_enabled is true (enabling takes
    // effect on the next tick — no restart — and a transient session death
    // auto-re-arms). When active, collect_fast drains it; there is NO poll
    // fallback (no snapshot-diff equivalent for image loads). Drained only under
    // collect_mu_.
    std::unique_ptr<yuzu::tar::ImageStreamCollector> module_stream_;
    std::atomic<bool> module_stream_active_{false};
    std::vector<yuzu::tar::ModuleEvent> pending_module_evs_;
    std::uint64_t last_module_dropped_{0};
    // Latches a failed start() so collect_fast does not retry every tick (start
    // storm) when the ETW session is genuinely unavailable; reset when the source
    // is disabled, so a later re-enable retries. Guarded by collect_mu_.
    bool module_start_failed_{false};

    // ── collect_fast: processes + network ─────────────────────────────────────
    // Unlocked implementation -- caller must hold collect_mu_
    // arp_pre/dns_pre: optionally pre-enumerated snapshots collected by the caller
    // BEFORE collect_mu_ was taken (the arp/dns collectors are syscall-heavy — see
    // do_collect_fast). When null, the leg enumerates inline (legacy/no-op path).
    int collect_fast_impl(yuzu::CommandContext& ctx,
                          std::vector<yuzu::tar::ArpEntry>* arp_pre = nullptr,
                          std::vector<yuzu::tar::DnsEntry>* dns_pre = nullptr) {
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
            // #538: single source of truth for the diff-baseline state key (see
            // diff_state_key) — the same key apply_source_enabled_transition
            // clears on disable, so the two can't drift.
            const std::string proc_key{yuzu::tar::diff_state_key("process")};
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
                            pending_stream_evs_.erase(pending_stream_evs_.begin(),
                                                      pending_stream_evs_.begin() +
                                                          static_cast<std::ptrdiff_t>(excess));
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
                    spdlog::warn(
                        "TAR: process stream ring overflow — {} dropped (+{} since last drain)", d,
                        d - last_logged_dropped_);
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
                    db_->set_state(proc_key, processes_to_json(current).dump());
                }
            } else {
                // No active stream (poll-only platform, or stream unavailable):
                // snapshot-diff poll.
                auto current = yuzu::agent::enumerate_processes();

                // Stabilization exclusions: drop processes whose name matches any
                // exclusion pattern. The patterns reuse the same matching as
                // redaction (case-insensitive substring with optional '*' on
                // either side stripped — NOT real glob). Excluded processes never enter the
                // diff, so their birth/death events are silently dropped — the
                // documented forensic-completeness trade-off.
                if (!stab_excl.empty()) {
                    std::erase_if(current, [&](const auto& p) {
                        return yuzu::tar::should_redact(p.name, stab_excl);
                    });
                }

                auto prev_json = db_->get_state(proc_key);
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

                db_->set_state(proc_key, processes_to_json(current).dump());
            }
        }

        // Network diff
        if (source_enabled(*db_, "tcp")) {
            // #538: tcp's diff baseline lives under "network" (see diff_state_key).
            const std::string net_key{yuzu::tar::diff_state_key("tcp")};
            auto current = yuzu::tar::enumerate_connections();
            auto prev_json = db_->get_state(net_key);
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

            db_->set_state(net_key, connections_to_json(current).dump());
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
            auto rows =
                yuzu::tar::select_netqual_rows(samples, ts, snap_id, yuzu::tar::kNetQualTopN);
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

        // ARP diff (ADR-0015). Opt-in: default_enabled=false in the registry, so
        // source_enabled returns false until an operator turns it on. Windows-only
        // collector today (enumerate_arp returns {} elsewhere). Non-fatal on insert
        // failure — the always-on legs above already committed, so a failure here
        // must not misreport a healthy tick; the diff baseline is advanced ONLY on
        // success so a failed insert retries the same deltas next tick.
        if (source_enabled(*db_, "arp")) {
            auto current = arp_pre ? std::move(*arp_pre) : yuzu::tar::enumerate_arp();
            auto previous = json_to_arp(db_->get_state("arp"));
            auto typed = yuzu::tar::compute_arp_events(previous, current, ts, snap_id);
            bool ok = true;
            if (!typed.empty()) {
                ok = db_->insert_arp_events(typed);
                if (ok)
                    total_events += static_cast<int>(typed.size());
                else
                    spdlog::error("TAR: arp insert failed this tick (state not advanced)");
            }
            if (ok)
                db_->set_state("arp", arp_to_json(current).dump());
        }

        // DNS-cache diff (ADR-0015). Opt-in (usage-class PII — visited domains).
        // Device-level resolver-cache state; NOT per-process (no pid). Same
        // non-fatal / advance-on-success discipline as the arp leg.
        if (source_enabled(*db_, "dns")) {
            auto current = dns_pre ? std::move(*dns_pre) : yuzu::tar::enumerate_dns();
            auto previous = json_to_dns(db_->get_state("dns"));
            auto typed = yuzu::tar::compute_dns_events(previous, current, ts, snap_id);
            bool ok = true;
            if (!typed.empty()) {
                ok = db_->insert_dns_events(typed);
                if (ok)
                    total_events += static_cast<int>(typed.size());
                else
                    spdlog::error("TAR: dns insert failed this tick (state not advanced)");
            }
            if (ok)
                db_->set_state("dns", dns_to_json(current).dump());
        }

        // M2: module/image loads (Windows ETW). OPT-IN (module_enabled, default
        // off) — like procperf/netqual this reads the explicit "true" rather than
        // source_enabled. The session is only running if it was enabled at init.
        const bool module_enabled = db_->get_config("module_enabled", "false") == "true";
        // Lazy start / re-arm: start the session on the first enabled tick (so
        // enabling takes effect next tick — like procperf/netqual, no restart) and
        // re-arm after a transient session death. module_start_failed_ prevents a
        // start-storm when the session is genuinely unavailable; it is reset on
        // disable so a later re-enable retries.
        if (module_stream_ && module_enabled && !module_stream_active_ && !module_start_failed_) {
            module_stream_active_ = module_stream_->start();
            if (module_stream_active_) {
                spdlog::info("TAR: module stream active ({})", module_stream_->method_name());
            } else {
                module_start_failed_ = true;
                spdlog::warn("TAR: module ETW session failed to start — module capture "
                             "unavailable (retries if module_enabled is toggled off then on)");
            }
        }
        if (!module_enabled) {
            module_start_failed_ = false; // re-enable should retry a previously-failed start
        }
        if (module_stream_active_ && !module_enabled) {
            // Disabled mid-run (a true→false toggle): drain-and-discard so the
            // paused window is never stored, keeping the session warm. Mirrors
            // the process forensic-pause contract.
            module_stream_->drain();
            pending_module_evs_.clear();
        } else if (module_stream_active_ && module_enabled) {
            // drain() resolves signing (cached) and redacts module_dir off the
            // ETW thread, so events arrive fully populated + privacy-scrubbed.
            auto mevs = module_stream_->drain();
            if (!pending_module_evs_.empty()) {
                mevs.insert(mevs.begin(), std::make_move_iterator(pending_module_evs_.begin()),
                            std::make_move_iterator(pending_module_evs_.end()));
                pending_module_evs_.clear();
            }
            // §5 edge risk-filter: keep every risky load, dedup + cap signed.
            mevs = yuzu::tar::apply_module_risk_filter(std::move(mevs));
            std::vector<yuzu::tar::ModuleRow> mrows;
            mrows.reserve(mevs.size());
            for (const auto& e : mevs) {
                yuzu::tar::ModuleRow r;
                r.ts = e.ts_unix;
                r.snapshot_id = snap_id;
                r.action = std::string{yuzu::tar::module_action_token(e.action)};
                r.pid = e.pid;
                r.process_name = e.process_name;
                r.module_name = e.module_name;
                r.module_dir = e.module_dir; // already redacted by the collector
                r.signed_state = std::string{yuzu::tar::module_signed_token(e.signed_state)};
                r.signer = e.signer;
                r.is_kernel = e.is_kernel;
                mrows.push_back(std::move(r));
            }
            if (!mrows.empty()) {
                if (!db_->insert_module_events(mrows)) {
                    // OPT-IN source: like netqual, do NOT fail the whole tick (the
                    // always-on legs already committed). Re-queue the filtered
                    // batch for the next tick, bounded, and log.
                    spdlog::error("TAR: module stream insert failed — re-queuing {} events",
                                  mevs.size());
                    pending_module_evs_ = std::move(mevs);
                    if (pending_module_evs_.size() > kPendingStreamCap) {
                        const auto excess = pending_module_evs_.size() - kPendingStreamCap;
                        pending_module_evs_.erase(pending_module_evs_.begin(),
                                                  pending_module_evs_.begin() +
                                                      static_cast<std::ptrdiff_t>(excess));
                    }
                } else {
                    total_events += static_cast<int>(mrows.size());
                }
            }
            if (auto d = module_stream_->dropped(); d > last_module_dropped_) {
                spdlog::warn("TAR: module stream ring overflow — {} dropped (+{} since last drain)",
                             d, d - last_module_dropped_);
                last_module_dropped_ = d;
            }
            // Self-heal: no poll fallback for modules — if the session ended, stop
            // and report module_capture_method=none (vs going silently blind).
            if (!module_stream_->running()) {
                spdlog::warn(
                    "TAR: module stream ended — module capture stopped (no poll fallback)");
                module_stream_->stop();
                module_stream_active_ = false;
            }
        }

        ctx.write_output(std::format("tar|collect_fast|{}|events_recorded", total_events));
        return 0;
    }

    int do_collect_fast(yuzu::CommandContext& ctx) {
        // SRE/UP-1: enumerate the syscall-heavy opt-in network sources (arp via
        // GetIpNetTable2; dns via DnsGetCacheDataTable + up to kDnsEntryCap cache-only
        // DnsQuery_W calls) BEFORE taking collect_mu_, so a large host cache cannot
        // stall the always-on process/tcp legs or the fleet-snapshot pump (mirrors
        // do_collect_perf's lock-free counter read). The diff/insert/state-save still
        // run under collect_mu_ inside collect_fast_impl.
        const bool arp_on = source_enabled(*db_, "arp");
        const bool dns_on = source_enabled(*db_, "dns");
        std::vector<yuzu::tar::ArpEntry> arp_pre;
        std::vector<yuzu::tar::DnsEntry> dns_pre;
        // Belt-and-suspenders (SRE): the dns collector calls an undocumented dnsapi
        // export over an opaque heap list; isolate any throw so a bad list degrades
        // this tick to empty rather than crossing the plugin ABI boundary.
        try {
            if (arp_on)
                arp_pre = yuzu::tar::enumerate_arp();
            if (dns_on)
                dns_pre = yuzu::tar::enumerate_dns();
        } catch (...) {
            spdlog::error("TAR: arp/dns enumeration threw; skipping this tick");
            arp_pre.clear();
            dns_pre.clear();
        }
        std::lock_guard lock(collect_mu_);
        return collect_fast_impl(ctx, arp_on ? &arp_pre : nullptr, dns_on ? &dns_pre : nullptr);
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
                bool perf_enabled_now = true;
                yuzu::tar::PerfSample sample;
                {
                    std::lock_guard lock(collect_mu_); // prev_perf_ RMW + disable re-check
                    // The enabled gate above ran WITHOUT the lock; a disable could
                    // have landed (and reset prev_perf_) since. Re-check here so a
                    // disable racing a mid-flight sample never commits a post-disable
                    // row, and leave prev_perf_ untouched when disabled so the reset
                    // in the disable branch stands. (#538)
                    perf_enabled_now = source_enabled(*db_, "perf");
                    if (perf_enabled_now) {
                        sample = yuzu::tar::derive_sample(prev_perf_, cur);
                        prev_perf_ = cur;
                    }
                }
                if (!perf_enabled_now) {
                    ctx.write_output("tar|collect_perf|0|source_disabled");
                } else if (!sample.valid) {
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
        bool procperf_enabled_now = true;
        std::vector<yuzu::tar::ProcPerfSample> samples;
        {
            std::lock_guard lock(collect_mu_); // prev_proc_ RMW + disable re-check
            // The procperf gate above ran WITHOUT the lock; re-check here so a
            // disable that raced this tick (and already reset prev_proc_) cannot
            // commit a post-disable row. Leave prev_proc_ as the disable branch
            // reset it so a later re-enable re-baselines instead of diffing across
            // the opt-out window. (#538)
            procperf_enabled_now = (db_->get_config("procperf_enabled", "false") == "true");
            if (procperf_enabled_now) {
                samples = yuzu::tar::derive_proc_samples(prev_proc_, proc_cur, redaction);
                prev_proc_ = std::move(proc_cur);
            }
        }
        if (!procperf_enabled_now) {
            ctx.write_output("tar|collect_procperf|0|source_disabled");
            return rc;
        }
        if (samples.empty()) {
            ctx.write_output("tar|collect_procperf|0|baseline");
            return rc;
        }
        // Resolve each app's on-disk file version OUTSIDE collect_mu_ — the
        // OpenProcess + version-resource read must never block other collectors.
        // No-op off Windows (versions stay ""). (#DEX app-perf-over-time slice 1)
        {
            std::lock_guard vlock(proc_ver_mu_);
            yuzu::tar::resolve_proc_versions(samples, version_cache_);
        }
        const auto snap_id = next_snapshot_id();
        std::vector<yuzu::tar::ProcPerfRow> rows;
        rows.reserve(samples.size());
        for (auto& s : samples) {
            yuzu::tar::ProcPerfRow r;
            r.ts = ts;
            r.snapshot_id = snap_id;
            r.name = std::move(s.name);
            r.version = std::move(s.version);
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
            const std::string svc_key{yuzu::tar::diff_state_key("service")}; // #538
            auto current = yuzu::tar::enumerate_services();
            auto prev_json = db_->get_state(svc_key);
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

            db_->set_state(svc_key, services_to_json(current).dump());
        }

        // User diff
        if (source_enabled(*db_, "user")) {
            const std::string usr_key{yuzu::tar::diff_state_key("user")}; // #538
            auto current = yuzu::tar::enumerate_users();
            auto prev_json = db_->get_state(usr_key);
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

            db_->set_state(usr_key, users_to_json(current).dump());
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
    // Scope: MACHINE-WIDE inventory only (HKLM Uninstall). The source carries no
    // user identity — an event is the host's software, never a Windows profile's —
    // so there is no per-user / NTUSER.DAT / hive-mount path (#1620). The source is
    // opt-in (default off): an operator turns it on per host.
    //
    // The enumeration — which on Windows walks the registry — runs OUTSIDE
    // collect_mu_ so a slow registry pass cannot stall collect_fast/slow/
    // fleet_snapshot under that shared lock (gov UP-6, mirrors collect_perf). Only
    // the state read-diff-write is locked.
    //
    // Cold start: the FIRST run on a host (no prior "software" state) seeds the
    // baseline WITHOUT emitting events — an 'installed' event must mean "installed
    // now", not "already present when the agent started watching". This is a
    // deliberate divergence from the service/user cold-start burst and mirrors the
    // process-stream fallback baseline seed.
    int do_collect_software(yuzu::CommandContext& ctx) {
        const auto ts = now_epoch_seconds();
        // Heartbeat: record that the tick fired regardless of outcome, so an
        // operator reading tar.status can tell "healthy but quiet" from "trigger
        // never ran" / "every tick errors" (the agent has no /metrics endpoint).
        db_->set_config("software_last_run_ts", std::to_string(ts));

        if (!source_enabled(*db_, "software")) {
            ctx.write_output("tar|collect_software|0|source_disabled");
            return 0;
        }

        std::lock_guard lock(software_collect_mu_); // serialises concurrent collect_software only
        // #538/#1620: the source_enabled gate above ran WITHOUT this lock; a
        // `tar.configure software_enabled=false` (do_configure) takes this SAME
        // lock to clear the baseline + flip the flag. Re-check under the lock so a
        // disable racing a mid-flight tick can neither insert events from the
        // paused window nor re-seed a baseline after the disable cleared it
        // (mirrors the perf/procperf post-lock re-check).
        if (!source_enabled(*db_, "software")) {
            ctx.write_output("tar|collect_software|0|source_disabled");
            return 0;
        }

        auto prev_json = db_->get_state("software");

        // Enumerate THIS tick's machine-scope inventory (HKLM Uninstall, 64-bit +
        // WOW6432Node). The enumeration runs OUTSIDE collect_mu_ (we hold only
        // software_collect_mu_), so a slow registry pass cannot stall
        // collect_fast/slow/fleet_snapshot.
        std::vector<yuzu::tar::SoftwareInfo> enumerated;
        yuzu::tar::enumerate_machine_software(enumerated);

        // Pure classify + diff (cold-start seed / corrupt-skip / steady), unit-tested
        // off-Windows in test_tar_software.cpp.
        const auto snap_id = next_snapshot_id();
        auto result = yuzu::tar::software_collect_core(prev_json, std::move(enumerated), ts, snap_id);
        using Kind = yuzu::tar::SoftwareCollectResult::Kind;
        switch (result.kind) {
        case Kind::kCorruptSkip:
            spdlog::error("TAR: software state is not a JSON array — skipping tick "
                          "(baseline preserved, not re-seeded)");
            ctx.write_output("tar|collect_software|0|state_unreadable");
            return 0;
        case Kind::kColdStartSeed:
            db_->set_state("software", result.new_state_json);
            ctx.write_output("tar|collect_software|0|baseline_seeded");
            return 0;
        case Kind::kSteady:
            if (!result.events.empty()) {
                if (!db_->insert_software_events(result.events)) {
                    spdlog::error("TAR: failed to insert software events, skipping state save");
                    ctx.write_output("error|software insert failed");
                    return 1;
                }
            }
            db_->set_state("software", result.new_state_json);
            ctx.write_output(
                std::format("tar|collect_software|{}|events_recorded", result.events.size()));
            return 0;
        }
        return 0; // unreachable — switch is exhaustive over Kind
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
            auto stored = db_->get_config(enabled_key, src.default_enabled ? "true" : "false");
            // #560 — emit a strict tri-state (true/false/errored). do_configure
            // only ever persists "true"/"false"; any other stored value was
            // written outside the plugin (corruption, disk tampering, a
            // downgrade/upgrade) and is surfaced as the explicit "errored"
            // sentinel so the dashboard renders a value-error badge instead of
            // silently omitting the source. Never coerced/guessed.
            auto enabled_val = yuzu::tar::canonical_source_enabled(stored);
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

        // Software source pacing + heartbeat. software_last_run_ts is the wall-clock
        // of the last collect_software tick (0 if it has never run) — the operator's
        // signal that the hourly trigger is alive even on a host with no software
        // changes (where software_live_rows stays 0).
        ctx.write_output(std::format("config|software_interval_seconds|{}",
                                     db_->get_config("software_interval_seconds", "3600")));
        ctx.write_output(std::format("config|software_last_run_ts|{}",
                                     db_->get_config("software_last_run_ts", "0")));

        // Mechanism actually in force. Only polling is wired today regardless of
        // the configured method (kPlanned methods like etw / endpoint_security are
        // accepted for pre-staging but not collected), so status can never
        // misrepresent the active capture mechanism to a forensic analyst (#1528).
        ctx.write_output(std::format("config|network_capture_method_effective|{}",
                                     yuzu::tar::effective_network_capture_method(net_method)));

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

        // M2 module-stream health — emitted UNCONDITIONALLY (same contract as the
        // process keys) so agentic consumers read by key presence without a
        // presence check. "none" when there is no live session: off-Windows, or
        // when module_enabled was false at start so the session never started.
        ctx.write_output(std::format(
            "config|module_capture_method|{}",
            (module_stream_active_ && module_stream_) ? module_stream_->method_name() : "none"));
        ctx.write_output(std::format("config|module_stream_dropped|{}",
                                     module_stream_ ? module_stream_->dropped() : 0));
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
        } else if (type_filter == "software") {
            sql = "SELECT ts, 'software' AS event_type, action, snapshot_id, "
                  "'' AS detail_json FROM software_live" +
                  where + tail;
        } else if (type_filter == "arp") {
            // ADR-0015. detail_json carries a human summary (ip @ mac [iface]); the
            // full row is available via tar.sql over $ARP_Live.
            sql = "SELECT ts, 'arp' AS event_type, action, snapshot_id, "
                  "(ip_address || ' @ ' || mac_address || ' [' || interface || ']') AS detail_json "
                  "FROM arp_live" +
                  where + tail;
        } else if (type_filter == "dns") {
            sql = "SELECT ts, 'dns' AS event_type, action, snapshot_id, "
                  "(name || ' ' || record_type || ' ' || data) AS detail_json "
                  "FROM dns_live" +
                  where + tail;
        } else {
            // No-filter union stays the core four-source event timeline. arp/dns
            // are device-state caches (opt-in, dns is PII) — reachable only via an
            // explicit type filter above or tar.sql, never the default feed.
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
                  where +
                  " UNION ALL "
                  "SELECT ts, 'software', action, snapshot_id, '' FROM software_live" +
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
        // For the "no filter" case we have to UNION ALL five tables that do
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
                              "  FROM user_live WHERE ts >= {} AND ts <= {} UNION ALL "
                              "SELECT 'software', ts, snapshot_id, action, "
                              "       (name || ' ' || COALESCE(version,'')) AS summary "
                              "  FROM software_live WHERE ts >= {} AND ts <= {}"
                              ") ORDER BY ts ASC LIMIT {}",
                              from, to, from, to, from, to, from, to, from, to, limit);
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
            else if (type_filter == "software")
                table = "software_live";
            else if (type_filter == "arp") // ADR-0015
                table = "arp_live";
            else if (type_filter == "dns") // ADR-0015
                table = "dns_live";
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
        // Pre-enumerate arp/dns lock-free (same rationale as do_collect_fast).
        const bool arp_on = source_enabled(*db_, "arp");
        const bool dns_on = source_enabled(*db_, "dns");
        std::vector<yuzu::tar::ArpEntry> arp_pre;
        std::vector<yuzu::tar::DnsEntry> dns_pre;
        // Belt-and-suspenders (SRE): the dns collector calls an undocumented dnsapi
        // export over an opaque heap list; isolate any throw so a bad list degrades
        // this tick to empty rather than crossing the plugin ABI boundary.
        try {
            if (arp_on)
                arp_pre = yuzu::tar::enumerate_arp();
            if (dns_on)
                dns_pre = yuzu::tar::enumerate_dns();
        } catch (...) {
            spdlog::error("TAR: arp/dns enumeration threw; skipping this tick");
            arp_pre.clear();
            dns_pre.clear();
        }
        {
            std::lock_guard lock(collect_mu_);
            collect_fast_impl(ctx, arp_on ? &arp_pre : nullptr, dns_on ? &dns_pre : nullptr);
            collect_slow_impl(ctx);
        }
        // Software lives on its own dedicated software_collect_mu_ (NOT collect_mu_),
        // so collect it as a SEPARATE step after the collect_mu_ scope closes —
        // preserving the collect_mu_ ≺ software_collect_mu_ lock order. It self-gates
        // on source_enabled("software"), so a disabled source is a no-op. The manual
        // promises `snapshot` collects all enabled capture sources (#1620).
        do_collect_software(ctx);
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
    // Redaction: load_redaction_patterns now unions kDefaultRedactionPatterns
    // (via ensure_redaction_defaults) internally, so an empty/all-dropped config
    // does NOT disable redaction on ANY collect path — this snapshot included
    // (governance round 1, sec-M1 + compliance-F3; #1532 fail-closed).
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

        // Redaction defaults are now unioned inside load_redaction_patterns (so
        // every collect path — collect_fast, procperf, and this snapshot — is
        // uniformly fail-closed; no stored value can disable *password*/*secret*/
        // *token*/*api_key*/*credential*). The previously-separate union here is
        // therefore redundant; keep the single source of truth in the loader.
        auto redaction = load_redaction_patterns(*db_);

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

        // M13 contract: validate EVERY parameter in the request in PHASE 1 and
        // only persist them in PHASE 2 once all pass. A request that mixes a
        // valid change with a later invalid one is therefore rejected atomically
        // — nothing is written. (Previously the writes were interleaved with the
        // validators, so e.g. a request carrying a valid `process_enabled=false`
        // followed by an invalid exclusion list would persist the disable —
        // silently turning off capture — yet return an error to the caller.)
        // No db_->set_config / apply_source_enabled_transition call happens until
        // the "Phase 2" block below; every path before it only reads + validates.

        // ── Phase 1: validate everything (no writes) ─────────────────────────
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

        // redaction_patterns — validate a JSON array of non-empty strings.
        const bool have_redaction = !redaction.empty();
        if (have_redaction) {
            try {
                auto arr = json::parse(std::string{redaction});
                if (!arr.is_array()) {
                    ctx.write_output("error|redaction_patterns must be a JSON array of strings");
                    return 1;
                }
                if (arr.size() > yuzu::tar::kMaxPatternArrayElements) {
                    ctx.write_output(std::format("error|redaction_patterns exceeds the {}-element "
                                                 "limit",
                                                 yuzu::tar::kMaxPatternArrayElements));
                    return 1;
                }
                for (const auto& elem : arr) {
                    if (!elem.is_string() || elem.get<std::string>().empty()) {
                        ctx.write_output(
                            "error|redaction_patterns must contain only non-empty strings");
                        return 1;
                    }
                    if (auto err = yuzu::tar::validate_config_pattern(
                            elem.get<std::string>(), /*require_min_core_len=*/false)) {
                        ctx.write_output(std::format("error|redaction_patterns: {}", *err));
                        return 1;
                    }
                }
            } catch (...) {
                ctx.write_output("error|redaction_patterns must be valid JSON array");
                return 1;
            }
        }

        // ── Per-source enable/disable (issue #59) ─────────────────────────────
        // Operators can disable any collector on a host without editing source.
        // Disabled collectors short-circuit in collect_fast/slow but still permit
        // `query` against existing rows. Collect the validated (source, value)
        // toggles here; the transition is applied in Phase 2. PR-A: enable→disable
        // records `<source>_paused_at` (wall-clock) for the retention-paused
        // dashboard list (#547); the reverse clears it to "0".
        std::vector<std::pair<std::string, std::string>> source_toggles;
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
            // M13 two-phase contract (#1532): collect the validated toggle now;
            // the actual transition (and its #538 collect_mu_ serialisation +
            // baseline reset) is applied in Phase 2, so a later invalid parameter
            // in the same request writes nothing.
            source_toggles.emplace_back(std::string{src.name}, std::move(v));
        }

        // ── Network capture method surface (issue #59) ───────────────────────
        // Today only "polling" is wired. ETW (Windows) and Endpoint Security
        // (macOS) are accepted-and-stored values per the schema registry's
        // OsSupport metadata so an operator can pre-stage the configuration, but
        // the collector continues to use polling until the implementation lands.
        const auto net_param = params.get("network_capture_method");
        const bool have_net = !net_param.empty();
        std::string net_method{net_param};
        if (have_net && net_method != "polling") {
            // "polling" is a sentinel meaning "use the platform default" — the
            // only mechanism wired today — and is accepted unconditionally even
            // though no os_support row carries it as a capture_method (governance
            // C-1 / QA Finding 2 round-trip). #540 — validate any other value
            // against THIS host's OS accept-list, not the OS-blind union, so a
            // Linux agent cannot store 'iphlpapi' nor a Windows agent 'procfs'.
            auto accepted =
                yuzu::tar::accepted_capture_methods_for_os("tcp", yuzu::tar::current_platform_os());
            if (std::find(accepted.begin(), accepted.end(), net_method) == accepted.end()) {
                std::string list = "polling";
                for (const auto& m2 : accepted) {
                    list += ",";
                    list += m2;
                }
                ctx.write_output(
                    std::format("error|network_capture_method '{}' is not accepted on this OS "
                                "(must be one of: {})",
                                net_method, list));
                return 1;
            }
        }

        // ── Process stabilization exclusions (issue #59) ─────────────────────
        // Case-insensitive substring patterns whose churn is excluded from
        // process events (noisy short-lived helpers). Validate here; persist in
        // Phase 2. Trade-off: anything matching is invisible to TAR, hence the
        // require_min_core_len floor that rejects over-broad 1–2 char patterns.
        const auto excl_param = params.get("process_stabilization_exclusions");
        const bool have_excl = !excl_param.empty();
        if (have_excl) {
            try {
                auto arr = json::parse(std::string{excl_param});
                if (!arr.is_array()) {
                    ctx.write_output("error|process_stabilization_exclusions must be a JSON array");
                    return 1;
                }
                if (arr.size() > yuzu::tar::kMaxPatternArrayElements) {
                    ctx.write_output(
                        std::format("error|process_stabilization_exclusions exceeds the {}-element "
                                    "limit",
                                    yuzu::tar::kMaxPatternArrayElements));
                    return 1;
                }
                for (const auto& elem : arr) {
                    if (!elem.is_string() || elem.get<std::string>().empty()) {
                        ctx.write_output("error|process_stabilization_exclusions must contain only "
                                         "non-empty strings");
                        return 1;
                    }
                    if (auto err = yuzu::tar::validate_config_pattern(
                            elem.get<std::string>(), /*require_min_core_len=*/true)) {
                        ctx.write_output(
                            std::format("error|process_stabilization_exclusions: {}", *err));
                        return 1;
                    }
                }
            } catch (...) {
                ctx.write_output("error|process_stabilization_exclusions must be valid JSON array");
                return 1;
            }
        }

        // ── Phase 2: persist (every parameter above is already validated) ────
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
        if (have_redaction) {
            db_->set_config("redaction_patterns", std::string{redaction});
            ctx.write_output(std::format("config|redaction_patterns|{}", redaction));
            changed = true;
        }
        for (const auto& [src_name, v] : source_toggles) {
            bool transition_ok;
            {
                // #538: collect_fast/slow hold collect_mu_ for their whole
                // enumerate→diff→set_state cycle. Taking it here makes the
                // enabled-flag write + baseline clear atomic w.r.t. a collection
                // tick: the tick either fully precedes the disable (its set_state
                // is then wiped by the baseline clear) or sees enabled=false and
                // skips. No interleaving ⇒ no post-disable snapshot, no ghost
                // "stopped" events on re-enable. No deadlock: do_configure runs
                // without collect_mu_ held and the helper re-acquires nothing.
                std::lock_guard lock(collect_mu_);
                // `software` keeps its baseline read-diff-write under the dedicated
                // software_collect_mu_, NOT collect_mu_ (its slow registry walk must
                // not stall collect_fast under the shared lock — gov UP-6). So for the
                // software transition also hold THAT lock, or the baseline clear +
                // flag flip is not atomic w.r.t. an in-flight collect_software tick and
                // the #538 ghost-event race reopens on the default-on software source
                // (#1620). Lock order is always collect_mu_ ≺ software_collect_mu_
                // (collect_software takes only the latter), so there is no inversion.
                std::unique_lock<std::mutex> sw_lock;
                if (src_name == "software")
                    sw_lock = std::unique_lock<std::mutex>(software_collect_mu_);
                transition_ok = yuzu::tar::apply_source_enabled_transition(*db_, src_name, v,
                                                                           now_epoch_seconds());
                if (transition_ok && v == "false") {
                    // The interval samplers (perf / procperf) keep their previous
                    // reading in memory, not in a diff-state row, so the
                    // diff_state_key clear inside apply_source_enabled_transition
                    // does not reach them (diff_state_key is empty for both). Reset
                    // the in-memory baseline under the SAME lock the collect legs
                    // take so a later re-enable diffs against a fresh reading instead
                    // of one from before the pause — otherwise the first
                    // post-re-enable row would cover the entire disabled window (a
                    // privacy leak on opt-in procperf, and contradicts the
                    // "re-enabling starts from a clean baseline" promise in
                    // docs/user-manual/tar.md). default-constructed → valid=false,
                    // which derive_sample/derive_proc_samples treat as "no baseline"
                    // (records nothing on the next tick).
                    if (src_name == "perf")
                        prev_perf_ = yuzu::tar::PerfCounters{};
                    else if (src_name == "procperf")
                        prev_proc_ = yuzu::tar::ProcSnapshot{};
                }
            }
            if (!transition_ok) {
                // #538/UP-1: a disable that could not clear the baseline leaves
                // the source ENABLED (fail-safe). This is an apply-time I/O failure
                // (a busy DB), not a validation failure — Phase 1 already validated
                // every parameter — so the two-phase atomicity contract still holds:
                // the only writes that could precede this are the scalar set_config
                // calls above, and the source stays enabled rather than being left
                // disabled with a stale baseline. Report it so the operator retries.
                ctx.write_output(std::format(
                    "error|{}_enabled disable failed: could not clear collection baseline "
                    "(database busy); source left enabled",
                    src_name));
                return 1;
            }
            ctx.write_output(std::format("config|{}_enabled|{}", src_name, v));
            // Echo the resulting paused_at so the dashboard sees the transition
            // timestamp without an extra status round-trip — single source of
            // truth (re-read, not re-derived).
            std::string paused_at_key = std::format("{}_paused_at", src_name);
            ctx.write_output(
                std::format("config|{}|{}", paused_at_key, db_->get_config(paused_at_key, "0")));
            changed = true;
        }
        if (have_net) {
            if (net_method != "polling") {
                // Surface that no kernel-event collector is wired yet so an
                // operator pre-staging 'etw' / 'endpoint_security' isn't
                // surprised the collector keeps polling under the hood.
                ctx.write_output(
                    std::format("warn|network_capture_method '{}' accepted but not yet "
                                "implemented; collector will continue polling",
                                net_method));
            }
            db_->set_config("network_capture_method", net_method);
            ctx.write_output(std::format("config|network_capture_method|{}", net_method));
            changed = true;
        }
        if (have_excl) {
            db_->set_config("process_stabilization_exclusions", std::string{excl_param});
            ctx.write_output(std::format("config|process_stabilization_exclusions|{}", excl_param));
            changed = true;
        }

        // Phase 1 returns early on any invalid parameter, so reaching here with
        // nothing changed means the request carried no recognised parameter.
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
