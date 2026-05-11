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

#include <nlohmann/json.hpp>
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

/// Defence-in-depth filter: a malformed agent payload should not be able to
/// poison ip_to_agent with a link-local address (169.254/16 IPv4 or fe80::/10
/// IPv6). The agent-side enumerate_local_ips() already filters these; this
/// is the second wall (governance round 1, cons-N3).
bool is_link_local_addr(std::string_view addr) {
    if (addr.empty())
        return false;
    // IPv4 169.254.x.x
    if (addr.size() >= 8 && addr.substr(0, 8) == "169.254.")
        return true;
    // IPv6 fe80::/10 -- first 10 bits are 1111111010, prefix "fe80:" through
    // "febf:" (case-insensitive). Also bracketed forms.
    auto bracket_off = (!addr.empty() && addr.front() == '[') ? 1u : 0u;
    if (addr.size() >= bracket_off + 4) {
        auto p = addr.substr(bracket_off, 4);
        if ((p[0] == 'f' || p[0] == 'F') && (p[1] == 'e' || p[1] == 'E')) {
            char c = p[2];
            // 8/9/a/b/A/B == fe80..febf
            if (c == '8' || c == '9' || c == 'a' || c == 'b' || c == 'A' || c == 'B') {
                return true;
            }
        }
    }
    return false;
}

/// Normalize an IPv6 string for ip_to_agent lookup. Strips bracket form
/// `[fd00::1]` -> `fd00::1` and strips zone-id suffix `fd00::1%eth0` ->
/// `fd00::1`. IPv4 addresses pass through unchanged. (governance round 1,
/// UP-7 IPv6 bracket-form inconsistency.)
std::string normalize_ip(std::string_view in) {
    std::string s(in);
    if (!s.empty() && s.front() == '[' && s.back() == ']')
        s = s.substr(1, s.size() - 2);
    auto pct = s.find('%');
    if (pct != std::string::npos)
        s.resize(pct);
    return s;
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
                                       std::chrono::milliseconds fetch_deadline,
                                       std::size_t max_snapshot_bytes)
    : fetcher_(std::move(fetcher)), nvd_(nvd), ttl_(ttl), fetch_deadline_(fetch_deadline),
      max_snapshot_bytes_(max_snapshot_bytes) {
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
    // Bound the wait at fetch_deadline + 2s slack so a hung fetcher cannot
    // wedge caller threads forever (governance round 1, UP-8 / CAP-2).
    if (slot.refilling) {
        refill_waiters_.fetch_add(1, std::memory_order_relaxed);
        const auto wait_bound = fetch_deadline_ + std::chrono::seconds(2);
        bool finished = slot.cv.wait_for(lk, wait_bound, [&] { return !slot.refilling; });
        if (!finished) {
            refill_wait_timeouts_.fetch_add(1, std::memory_order_relaxed);
            spdlog::warn("FleetTopologyStore: waiter timed out after {}ms; "
                         "returning whatever is in the slot (may be null)",
                         wait_bound.count());
            // Fall through and return whatever the slot holds (possibly stale
            // or null). Do NOT attempt to take over the refill -- the original
            // owner is still running and we'd race with their final state
            // write.
            return slot.snap
                       ? slot.snap
                       : std::make_shared<const TopologySnapshot>(empty_snapshot(include_vuln));
        }
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
    // PR 6 / OBS-2: snapshot the observer under the lock so we don't race
    // with set_fetch_duration_observer if someone re-wires it during
    // bring-up. The observer call itself happens after we drop the lock.
    auto observer_snapshot = fetch_observer_;
    lk.unlock();

    std::shared_ptr<const TopologySnapshot> result;
    const auto fetch_started = std::chrono::steady_clock::now();
    try {
        auto raw = fetcher_(fetch_deadline_);
        result =
            std::make_shared<const TopologySnapshot>(build_snapshot(std::move(raw), include_vuln));
    } catch (const std::exception& ex) {
        spdlog::error("FleetTopologyStore: fetcher threw: {}", ex.what());
        // Fall through with result==nullptr; published below.
    } catch (...) {
        spdlog::error("FleetTopologyStore: fetcher threw unknown exception");
    }
    // PR 6 / OBS-2: emit the duration even on exception so a hung fetcher
    // produces a visible upper-bound observation rather than silently
    // missing from the histogram. Wrapped in try/catch so a misbehaving
    // observer cannot poison the refill path.
    if (observer_snapshot) {
        try {
            const auto elapsed =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - fetch_started);
            observer_snapshot(elapsed);
        } catch (...) {
            // Observer threw; swallow to keep the store reliable.
        }
    }

    // Memory-bound check: if the serialised snapshot exceeds max_snapshot_bytes_,
    // log a WARN and refuse to cache it. Caller still gets the snapshot for this
    // request, but the next get() will refill rather than serve a multi-GB blob.
    // (governance round 1, CAP-1.)
    bool oversize = false;
    if (result && max_snapshot_bytes_ > 0) {
        // dump() is O(N) on the snapshot; only run on cache miss (rare).
        nlohmann::json j = *result;
        const auto serialised_size = j.dump().size();
        if (serialised_size > max_snapshot_bytes_) {
            oversize = true;
            refill_oversize_drops_.fetch_add(1, std::memory_order_relaxed);
            spdlog::warn("FleetTopologyStore: refill {} bytes exceeds cap {}; "
                         "returning to caller but NOT caching",
                         serialised_size, max_snapshot_bytes_);
        }
    }

    lk.lock();
    if (result && !oversize) {
        slot.snap = result;
        slot.cached_at = std::chrono::steady_clock::now();
    }
    slot.refilling = false;
    slot.cv.notify_all();
    // UP-9: never return nullptr -- callers (PR 3 REST) must always have a
    // valid snapshot to render. Return the materialised oversize snapshot if
    // we have one, the stale cached value if we have one, or an empty sentinel.
    if (result)
        return result;
    if (slot.snap)
        return slot.snap;
    return std::make_shared<const TopologySnapshot>(empty_snapshot(include_vuln));
}

TopologySnapshot FleetTopologyStore::empty_snapshot(bool include_vuln) const {
    TopologySnapshot out;
    out.generated_at = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
    out.include_vuln = include_vuln;
    return out;
}

void FleetTopologyStore::invalidate() {
    std::lock_guard lk(slots_mu_);
    for (auto& [_, slot] : slots_) {
        slot->snap.reset();
    }
}

void FleetTopologyStore::set_fetch_duration_observer(FetchDurationObserver observer) {
    std::lock_guard lk(slots_mu_);
    fetch_observer_ = std::move(observer);
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
    // Skip 0.0.0.0/:: (ambiguous across hosts), loopback, and link-local.
    // Normalize bracketed/zone-id IPv6 forms so dst lookups in pass 2 hit
    // (governance round 1, cons-N3 + UP-7).
    // Pre-size the map to avoid 5-8 rehash cycles at 1000-agent scale.
    std::unordered_map<std::string, std::string> ip_to_agent;
    ip_to_agent.reserve(raw.size() * 4);
    for (const auto& r : raw) {
        if (r.stale)
            continue;
        for (const auto& ip : r.local_ips) {
            if (is_unspecified_addr(ip) || is_loopback_addr(ip) || is_link_local_addr(ip))
                continue;
            ip_to_agent.emplace(normalize_ip(ip), r.agent_id);
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
            // PR 2 ships the seam wired but inert: nvd_db.match_inventory
            // skips items where version.empty(), so this call returns no
            // matches today. PR 10 (vulnerability overlay) will either ship
            // installed versions in fleet_snapshot.v1 or extend NVD with a
            // name-only path. The seam is preserved so test fixtures that
            // populate match_inventory do exercise the propagation logic
            // below.
            inv.push_back({key, ""});
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
                auto it = ip_to_agent.find(normalize_ip(c.remote_addr));
                if (it != ip_to_agent.end() && it->second != r.agent_id) {
                    e.scope = EdgeScope::InternalFleet;
                    e.dst_agent_id = it->second;
                } else {
                    e.scope = EdgeScope::External;
                }
            }
            m.connections.push_back(std::move(e));
        }

        // PR 8 -- pair each Local-scope edge with its reciprocal half so the
        // renderer can draw interior lines. A loopback TCP session shows up
        // as two ESTABLISHED rows in the kernel socket table; the matching
        // peer has swapped (addr, port) on each side. Set dst_pid to the
        // peer's src_pid when matched. Unmatched halves are dropped because
        // the renderer cannot draw a line into the void. O(n^2) per machine
        // -- acceptable for typical per-host connection counts; a
        // (addr,port)->pid hash index is a refactor candidate once n
        // routinely exceeds a few hundred.
        for (auto& e : m.connections) {
            if (e.scope != EdgeScope::Local)
                continue;
            for (const auto& other : m.connections) {
                if (other.scope != EdgeScope::Local)
                    continue;
                if (other.src_addr == e.dst_addr && other.src_port == e.dst_port &&
                    other.dst_addr == e.src_addr && other.dst_port == e.src_port) {
                    e.dst_pid = other.src_pid;
                    break;
                }
            }
        }
        std::erase_if(m.connections, [](const ConnectionEdge& e) {
            return e.scope == EdgeScope::Local && e.dst_pid == 0;
        });

        out.machines.push_back(std::move(m));
    }

    return out;
}

} // namespace yuzu::server
