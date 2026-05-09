/**
 * fleet_topology_store.cpp -- aggregator + cache + IP/scope/vuln join
 *
 * The single-flight refill path uses a cv on the slot itself rather than
 * a separate "refill in progress" sentinel: callers see refilling=true,
 * wait for the cv, and re-check freshness on wake. The fetcher runs
 * outside the slots_mu_ so other slot reads are not blocked by dispatch.
 */

#include "fleet_topology_store.hpp"

#include "nvd_db.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace yuzu::server {

namespace {

bool is_unspecified_addr(std::string_view addr) {
    return addr == "0.0.0.0" || addr == "::" || addr == "[::]" || addr == "0:0:0:0:0:0:0:0";
}

bool is_loopback_addr(std::string_view addr) {
    if (addr.empty())
        return false;
    if (addr == "::1" || addr == "[::1]")
        return true;
    if (addr.size() >= 4 && addr.substr(0, 4) == "127.")
        return true;
    return false;
}

std::string lowercase(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

/// Severity rank for "worst CVE" picking. Higher = worse.
int severity_rank(std::string_view sev) {
    if (sev == "CRITICAL" || sev == "critical")
        return 4;
    if (sev == "HIGH" || sev == "high")
        return 3;
    if (sev == "MEDIUM" || sev == "medium")
        return 2;
    if (sev == "LOW" || sev == "low")
        return 1;
    return 0;
}

std::string severity_canonical(std::string_view sev) {
    return lowercase(std::string(sev)); // "critical" / "high" / "medium" / "low"
}

} // namespace

// -- Construction -------------------------------------------------------------

FleetTopologyStore::FleetTopologyStore(Fetcher fetcher, NvdDatabase* nvd,
                                       std::chrono::milliseconds ttl,
                                       std::chrono::milliseconds fetch_deadline)
    : fetcher_(std::move(fetcher)), nvd_(nvd), ttl_(ttl), fetch_deadline_(fetch_deadline) {
    slots_.emplace(false, std::make_unique<Slot>());
    slots_.emplace(true, std::make_unique<Slot>());
}

bool FleetTopologyStore::fresh_locked(const Slot& s) const {
    if (!s.snap)
        return false;
    auto age = std::chrono::steady_clock::now() - s.cached_at;
    return age < ttl_;
}

// -- get + single-flight refill -----------------------------------------------

std::shared_ptr<const TopologySnapshot> FleetTopologyStore::get(bool include_vuln) {
    std::unique_lock lk(slots_mu_);
    auto& slot = *slots_.at(include_vuln);

    // Fast path: cached snapshot is still warm.
    if (fresh_locked(slot)) {
        cache_hits_.fetch_add(1, std::memory_order_relaxed);
        return slot.snap;
    }

    // Single-flight: if another caller is refilling, wait for them to finish.
    if (slot.refilling) {
        refill_waiters_.fetch_add(1, std::memory_order_relaxed);
        slot.cv.wait(lk, [&] { return !slot.refilling; });
        // Whoever finished the refill might have failed; the caller-of-record
        // returns whatever they wrote, which may be the stale-but-replaced
        // snapshot or a brand-new one. Either way, return it.
        if (slot.snap) {
            cache_hits_.fetch_add(1, std::memory_order_relaxed);
            return slot.snap;
        }
        // No snap stored at all (initial fetch failed). Fall through to retry
        // ourselves. This is rare -- only happens if the fetcher threw.
    }

    // Take ownership of the refill.
    slot.refilling = true;
    cache_misses_.fetch_add(1, std::memory_order_relaxed);
    lk.unlock();

    std::shared_ptr<const TopologySnapshot> result;
    try {
        auto raw = fetcher_(fetch_deadline_);
        result =
            std::make_shared<const TopologySnapshot>(build_snapshot(std::move(raw), include_vuln));
    } catch (const std::exception& ex) {
        spdlog::error("FleetTopologyStore: fetcher threw: {}", ex.what());
        // Leave result empty; we'll publish nothing and unblock waiters.
    } catch (...) {
        spdlog::error("FleetTopologyStore: fetcher threw unknown exception");
    }

    lk.lock();
    if (result) {
        slot.snap = result;
        slot.cached_at = std::chrono::steady_clock::now();
    }
    slot.refilling = false;
    slot.cv.notify_all();
    return slot.snap; // may be null on first-call failure
}

void FleetTopologyStore::invalidate() {
    std::lock_guard lk(slots_mu_);
    for (auto& [_, slot] : slots_) {
        slot->snap.reset();
    }
}

// -- build_snapshot (the actual aggregation) ----------------------------------

TopologySnapshot FleetTopologyStore::build_snapshot(std::vector<RawAgentSnapshot> raw,
                                                    bool include_vuln) const {
    TopologySnapshot out;
    out.generated_at = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
    out.include_vuln = include_vuln;

    // ── Pass 1: build ip_to_agent map for cross-machine resolution ───────
    // Skip 0.0.0.0/::; those resolve ambiguously across hosts.
    std::unordered_map<std::string, std::string> ip_to_agent;
    for (const auto& r : raw) {
        if (r.stale)
            continue;
        for (const auto& ip : r.local_ips) {
            if (is_unspecified_addr(ip) || is_loopback_addr(ip))
                continue;
            ip_to_agent.emplace(ip, r.agent_id);
        }
    }

    // ── Optional: vuln overlay -- one match_inventory call per agent ──
    // (per agent rather than fleet-wide so the per-process result mapping
    // stays tractable; NVD lookups are cheap).
    auto match_for = [&](const RawAgentSnapshot& r) {
        std::unordered_map<std::string, CveMatch> by_name; // worst per name
        std::unordered_map<std::string, int> count_by_name;
        if (!include_vuln || !nvd_)
            return std::pair{by_name, count_by_name};

        std::vector<SoftwareItem> inv;
        std::unordered_set<std::string> seen;
        for (const auto& p : r.processes) {
            auto key = lowercase(p.name);
            if (key.empty() || !seen.insert(key).second)
                continue;
            inv.push_back({key, ""}); // version empty -> NVD does name-only match
        }
        auto matches = nvd_->match_inventory(inv);
        for (const auto& m : matches) {
            auto key = lowercase(m.product);
            ++count_by_name[key];
            auto it = by_name.find(key);
            if (it == by_name.end() ||
                severity_rank(m.severity) > severity_rank(it->second.severity)) {
                by_name[key] = m;
            }
        }
        return std::pair{by_name, count_by_name};
    };

    // ── Pass 2: build MachineNodes ─────────────────────────────────────
    out.machines.reserve(raw.size());
    for (const auto& r : raw) {
        MachineNode m;
        m.agent_id = r.agent_id;
        m.hostname = r.hostname;
        m.os = r.os;
        m.local_ips = r.local_ips;
        m.ts = r.ts;
        m.stale = r.stale;
        m.truncated_processes = r.truncated_processes;
        m.truncated_connections = r.truncated_connections;

        auto [vuln_by_name, count_by_name] = match_for(r);

        m.processes.reserve(r.processes.size());
        for (const auto& p : r.processes) {
            ProcessNode node;
            node.pid = p.pid;
            node.ppid = p.ppid;
            node.name = p.name;
            node.user = p.user;
            node.category = classify(p.name, p.user);
            if (include_vuln && nvd_) {
                auto key = lowercase(p.name);
                auto it = vuln_by_name.find(key);
                if (it != vuln_by_name.end()) {
                    node.worst_severity = severity_canonical(it->second.severity);
                    node.cve_count = count_by_name[key];
                }
            }
            m.processes.push_back(std::move(node));
        }

        m.connections.reserve(r.connections.size());
        for (const auto& c : r.connections) {
            ConnectionEdge e;
            e.proto = c.proto;
            e.src_pid = c.pid;
            e.src_addr = c.local_addr;
            e.src_port = c.local_port;
            e.dst_addr = c.remote_addr;
            e.dst_port = c.remote_port;
            e.state = c.state;

            // Skip listening sockets with no remote endpoint -- they
            // would render as edges into the void.
            if (c.remote_addr.empty() || c.remote_port == 0) {
                continue;
            }

            if (is_loopback_addr(c.local_addr) && is_loopback_addr(c.remote_addr)) {
                e.scope = EdgeScope::Local;
            } else {
                auto it = ip_to_agent.find(c.remote_addr);
                if (it != ip_to_agent.end() && it->second != r.agent_id) {
                    e.scope = EdgeScope::InternalFleet;
                    e.dst_agent_id = it->second;
                } else {
                    e.scope = EdgeScope::External;
                }
            }
            m.connections.push_back(std::move(e));
        }

        out.machines.push_back(std::move(m));
    }

    return out;
}

} // namespace yuzu::server
