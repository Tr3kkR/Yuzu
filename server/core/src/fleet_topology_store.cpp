/**
 * fleet_topology_store.cpp -- aggregator + cache + IP/scope/vuln join
 *
 * The single-flight refill path uses a cv on the slot itself rather than
 * a separate "refill in progress" sentinel: callers see refilling=true,
 * wait for the cv, and re-check freshness on wake. The fetcher runs
 * outside the slots_mu_ so other slot reads are not blocked by dispatch.
 */

#include "fleet_topology_store.hpp"

#include "audit_store.hpp"
#include "nvd_db.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <limits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace yuzu::server {

namespace {

// Per-field size cap for agent-reported address strings (Gate 7 UP-1 fix).
// IPv6 canonical max is 39 chars; brackets + zone-id push that to ~60.
// 64 is a generous upper bound that still bounds the worst-case wire
// payload regardless of how many LISTEN rows the agent ships. An agent
// sending a longer value is either buggy or hostile — silently truncate
// and log so an operator chasing a malformed listener has a breadcrumb.
constexpr std::size_t kAddressMaxLen = 64;

// Truncate-or-pass for the parser. Empty strings are returned unchanged;
// over-long strings are clipped at kAddressMaxLen. Caller emits a single
// spdlog warn line on truncation so chasing a malformed listener has a
// breadcrumb without flooding logs (one line per agent per snapshot).
inline std::string clamp_address(std::string s) {
    if (s.size() > kAddressMaxLen)
        s.resize(kAddressMaxLen);
    return s;
}

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
    // IPv4-mapped-in-IPv6 loopback (`::ffff:127.x.x.x` and bracket-wrapped
    // `[::ffff:127.x.x.x]`) — seen on dual-stack Linux when a binder uses
    // AF_INET6 without IPV6_V6ONLY. Gate 7 S-2 alignment with the
    // renderer-side isLoopbackBind (yuzu-viz.js).
    {
        auto s = addr;
        if (!s.empty() && s.front() == '[' && s.back() == ']')
            s = s.substr(1, s.size() - 2);
        if (s.size() >= 11 && (s[0] == ':') && (s[1] == ':') &&
            (s.substr(2, 5) == "ffff:" || s.substr(2, 5) == "FFFF:") && s.substr(7, 4) == "127.")
            return true;
    }
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
        // PR 10 / UAT 2026-05-12 — Push-first refill. If any agent has
        // pushed a snapshot via heartbeat (HeartbeatRequest.fleet_snapshot_json
        // → push_snapshot()), build the aggregate from the pushed map
        // and skip the legacy dispatch entirely. Cache-miss latency
        // drops from ~5 s (waiting on dispatched responses) to ~ms (a
        // map walk + JSON build), and slow responders no longer get
        // marked stale just because the gateway batched them past the
        // fetch deadline.
        //
        // PR 10 hardening — copy shared_ptr handles only (UP-15). At
        // 100k agents this is an O(N) pointer walk under pushed_mu_
        // (~1 MB working set) instead of an O(N×K) deep copy (~1 GB).
        // pushed_mu_ is released promptly so concurrent pushes don't
        // queue behind the refill.
        //
        // Legacy dispatch fetcher_() runs only when pushed_ is empty
        // (first boot, no agent has heartbeated yet).
        std::vector<std::shared_ptr<const RawAgentSnapshot>> pushed_handles;
        {
            std::lock_guard plk(pushed_mu_);
            if (!pushed_.empty()) {
                pushed_handles.reserve(pushed_.size());
                for (const auto& [_, snap_ptr] : pushed_)
                    pushed_handles.push_back(snap_ptr);
            }
        }
        std::vector<RawAgentSnapshot> raw;
        if (!pushed_handles.empty()) {
            raw.reserve(pushed_handles.size());
            for (const auto& sp : pushed_handles)
                raw.push_back(*sp); // copy is unavoidable for build_snapshot
        } else {
            raw = fetcher_(fetch_deadline_);
        }
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

// PR 10 hardening — sanitise an agent-controlled string before it
// crosses into a log line or AuditEvent.detail. Strips control bytes
// (`< 0x20 || == 0x7f`) AND any byte with the high bit set
// (multi-byte UTF-8 continuation bytes 0x80–0xff). The result is
// strict 7-bit ASCII with control chars replaced by spaces, capped
// at `max_len`. Used by sec-M3 / UP-14 (parse-exception log) and by
// audit-detail composition (Gate 7 HIGH: agent-controlled `ip` /
// `agent_id` going into `topology.push.rejected` detail).
static std::string sanitise_for_audit(std::string_view in, std::size_t max_len = 128) {
    std::string out;
    out.reserve(std::min(in.size(), max_len));
    for (auto c : in) {
        if (out.size() >= max_len)
            break;
        unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7f || u >= 0x80) {
            out.push_back(' ');
        } else {
            out.push_back(static_cast<char>(u));
        }
    }
    return out;
}

// PR 10 hardening — single shared JSON parser for fleet_snapshot.v1.
//
// Called from every ingestion site (server.cpp dispatch fetcher,
// AgentServiceImpl::Heartbeat, GatewayUpstreamServiceImpl::BatchHeartbeat)
// so the field set, default values, exception scope, row caps, and
// trust boundary stay in lock-step (arch-B3 / cons-S1). Free function
// because it has no dependency on store state.
//
// Caps enforced:
//   • Payload byte size — kPushedSnapshotMaxBytes; reject before parse
//     so a JSON-bomb cannot consume parser CPU (UP-8).
//   • `processes[]` length — kPushedSnapshotMaxRows; reject the whole
//     snapshot if exceeded (the producing agent caps at this too, so
//     legit snapshots never trip it).
//   • `connections[]` length — same cap as processes.
//
// Trust boundary: `agent_id` and `os` are passed in from the caller
// (session-authenticated) and never sourced from JSON. The JSON's
// `hostname`, `local_ips`, etc. are agent-controlled and may be
// fabricated; callers that need cross-agent validation (UP-1
// local_ips spoofing) MUST apply it after this parser returns.
std::optional<RawAgentSnapshot>
FleetTopologyStore::parse_fleet_snapshot_json(std::string_view json, std::string agent_id,
                                              std::string os, std::string* ex_message) {
    if (json.empty()) {
        if (ex_message)
            *ex_message = "empty payload";
        return std::nullopt;
    }
    if (json.size() > kPushedSnapshotMaxBytes) {
        if (ex_message)
            *ex_message = "payload exceeds " + std::to_string(kPushedSnapshotMaxBytes) + " bytes";
        return std::nullopt;
    }
    try {
        auto j = nlohmann::json::parse(json);
        RawAgentSnapshot rs;
        rs.agent_id = std::move(agent_id);
        rs.os = std::move(os);
        rs.hostname = j.value("hostname", std::string{});
        rs.ts = j.value("ts", 0LL);
        if (j.contains("local_ips") && j["local_ips"].is_array()) {
            // Bound local_ips length too — modest, but prevents a runaway
            // agent declaring 100k IPs to bloat the cube_world_pos map.
            constexpr std::size_t kMaxLocalIps = 64;
            for (const auto& ip : j["local_ips"]) {
                if (rs.local_ips.size() >= kMaxLocalIps)
                    break;
                if (ip.is_string())
                    rs.local_ips.push_back(ip.get<std::string>());
            }
        }
        rs.truncated_processes = j.value("truncated_processes", false);
        rs.truncated_connections = j.value("truncated_connections", false);
        if (j.contains("processes") && j["processes"].is_array()) {
            const auto& procs = j["processes"];
            if (procs.size() > kPushedSnapshotMaxRows) {
                if (ex_message)
                    *ex_message = "processes[] exceeds row cap (" + std::to_string(procs.size()) +
                                  " > " + std::to_string(kPushedSnapshotMaxRows) + ")";
                return std::nullopt;
            }
            rs.processes.reserve(procs.size());
            for (const auto& p : procs) {
                RawAgentSnapshot::RawProcess rp;
                rp.pid = p.value("pid", 0u);
                rp.ppid = p.value("ppid", 0u);
                rp.name = p.value("name", "");
                rp.cmdline = p.value("cmdline", "");
                rp.user = p.value("user", "");
                rs.processes.push_back(std::move(rp));
            }
        }
        if (j.contains("connections") && j["connections"].is_array()) {
            const auto& conns = j["connections"];
            if (conns.size() > kPushedSnapshotMaxRows) {
                if (ex_message)
                    *ex_message = "connections[] exceeds row cap (" + std::to_string(conns.size()) +
                                  " > " + std::to_string(kPushedSnapshotMaxRows) + ")";
                return std::nullopt;
            }
            rs.connections.reserve(conns.size());
            for (const auto& c : conns) {
                // Gate 7 MEDIUM — port-range sanity check. Out-of-range
                // ports cannot represent a real socket; allowing them
                // through pollutes EndpointKey hashes and renderer
                // socket maps. We skip the row rather than reject the
                // whole snapshot (one malformed row from a buggy agent
                // shouldn't blank out the cube).
                int lp = c.value("local_port", 0);
                int rp = c.value("remote_port", 0);
                if (lp < 0 || lp > 65535 || rp < 0 || rp > 65535)
                    continue;
                RawAgentSnapshot::RawConnection rc;
                rc.proto = c.value("proto", "");
                // Gate 7 UP-1: per-field size cap on agent-reported
                // addresses. A buggy or hostile agent sending a 1.9 MiB
                // `local_addr` value would otherwise sail through the
                // 2 MiB whole-payload cap and balloon downstream wire JSON.
                // Truncate at kAddressMaxLen — an IPv6+zone canonical form
                // is < 64 bytes.
                {
                    std::string la = c.value("local_addr", "");
                    if (la.size() > kAddressMaxLen) {
                        spdlog::warn(
                            "fleet_topology: agent={} clamped local_addr ({} bytes -> {}); "
                            "possible malformed or hostile snapshot",
                            agent_id, la.size(), kAddressMaxLen);
                        la.resize(kAddressMaxLen);
                    }
                    rc.local_addr = std::move(la);
                }
                rc.local_port = lp;
                {
                    std::string ra = c.value("remote_addr", "");
                    if (ra.size() > kAddressMaxLen) {
                        spdlog::warn(
                            "fleet_topology: agent={} clamped remote_addr ({} bytes -> {})",
                            agent_id, ra.size(), kAddressMaxLen);
                        ra.resize(kAddressMaxLen);
                    }
                    rc.remote_addr = std::move(ra);
                }
                rc.remote_host = c.value("remote_host", "");
                rc.remote_port = rp;
                rc.state = c.value("state", "");
                rc.pid = c.value("pid", 0u);
                rc.process_name = c.value("process_name", "");
                rs.connections.push_back(std::move(rc));
            }
        }
        return rs;
    } catch (const std::exception& ex) {
        // Strip control characters AND high-bit bytes via the shared
        // sanitiser (Gate 7 HIGH — multi-byte UTF-8 continuation bytes
        // would otherwise survive and could carry C1 control codes).
        if (ex_message)
            *ex_message = sanitise_for_audit(ex.what(), 256);
        return std::nullopt;
    }
}

// PR 10 / UAT 2026-05-12 — push-based ingestion entry point.
//
// Heartbeat dispatcher calls this whenever an agent attaches a
// fleet_snapshot.v1 payload. We replace any previous entry for the
// agent (latest snapshot wins).
//
// PR 10 hardening — does NOT invalidate the slot cache (perf-B1 /
// UP-6). At 100k-agent / 30s heartbeat cadence the previous
// behaviour fired invalidate() ~3,333×/s, thrashing the cache to a
// near-zero hit rate and serialising every reader behind every
// pusher. The slot cache now ages out via its normal TTL (60 s by
// default), which still bounds rendered staleness — pushed_ is the
// source of truth at refill time anyway.
//
// PR 10 hardening — UP-1 IP-spoofing defence. We index local_ips →
// agent_id and reject a push whose local_ips overlap an OTHER agent's
// claim. First-claim-wins; an agent re-claiming its own previously
// reported IPs is fine. Rejection is loud (counter + spdlog::warn)
// but non-fatal — the agent simply doesn't render until it stops
// claiming a peer's IP.
void FleetTopologyStore::push_snapshot(RawAgentSnapshot raw) {
    if (raw.agent_id.empty())
        return;
    // Capture agent_id up front — `raw` is moved into the map below
    // and we may need the id for audit emission AFTER the lock is
    // dropped (AuditStore::log takes its own locks; we don't want to
    // nest).
    const std::string agent_id = raw.agent_id;
    bool first_push_for_this_agent = false;
    std::string spoof_detail;
    {
        std::lock_guard plk(pushed_mu_);

        // UP-1 defence — scan claimed IPs against the index. A claim
        // that's already owned by THIS agent_id is fine (re-push of
        // same agent's snapshot); a conflict with any OTHER agent_id
        // is a spoofing attempt and we reject the whole push.
        for (const auto& ip : raw.local_ips) {
            auto it = ip_owner_.find(ip);
            if (it != ip_owner_.end() && it->second != agent_id) {
                pushed_rejected_count_.fetch_add(1, std::memory_order_relaxed);
                spdlog::warn("FleetTopologyStore: rejecting push from agent={} — claimed "
                             "local_ip={} is already owned by agent={} (UP-1 IP-spoof guard)",
                             agent_id, ip, it->second);
                // Gate 7 HIGH — sanitise every component that may have
                // been agent-controlled before it crosses into
                // AuditEvent.detail. `ip` is agent-controlled
                // (attacker-pushed JSON). `agent_id` is session-trusted
                // but enrollment-name-influenced so we sanitise it too,
                // following the defensive default. `it->second` is the
                // existing owner's session-trusted agent_id.
                spoof_detail = "claimant=" + sanitise_for_audit(agent_id) +
                               " ip=" + sanitise_for_audit(ip) +
                               " owner=" + sanitise_for_audit(it->second);
                break;
            }
        }
        if (!spoof_detail.empty()) {
            // Fall through to audit emission outside the lock (below).
        } else {
            first_push_for_this_agent = audited_first_push_.insert(agent_id).second;

            // Remove previous ip_owner_ entries for this agent (its IPs may
            // have changed since the last push — e.g. DHCP rebind) and
            // install the new set.
            for (auto it = ip_owner_.begin(); it != ip_owner_.end();) {
                if (it->second == raw.agent_id)
                    it = ip_owner_.erase(it);
                else
                    ++it;
            }
            for (const auto& ip : raw.local_ips)
                ip_owner_[ip] = raw.agent_id;

            // CAP-1 (#1002): bound the map. When at cap and inserting a
            // NEW agent_id, evict the entry with the smallest `ts` (oldest
            // push). A re-push of an already-present agent_id replaces in
            // place and doesn't trip the cap. Hot-path cost is O(N) over
            // the map only on the cap edge; uncapped pushes are O(1).
            if (pushed_map_cap_ > 0 && !pushed_.contains(agent_id) &&
                pushed_.size() >= pushed_map_cap_) {
                auto victim = pushed_.end();
                int64_t victim_ts = std::numeric_limits<int64_t>::max();
                for (auto it = pushed_.begin(); it != pushed_.end(); ++it) {
                    const int64_t t = it->second ? it->second->ts : 0;
                    if (t < victim_ts) {
                        victim_ts = t;
                        victim = it;
                    }
                }
                if (victim != pushed_.end()) {
                    // Also drop the evicted agent's ip_owner_ claims so a
                    // re-enrollment with overlapping IPs isn't rejected.
                    const std::string& vid = victim->first;
                    for (auto it = ip_owner_.begin(); it != ip_owner_.end();) {
                        if (it->second == vid)
                            it = ip_owner_.erase(it);
                        else
                            ++it;
                    }
                    pushed_.erase(victim);
                    pushed_evicted_for_cap_.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Store the snapshot as a shared_ptr<const> — readers in
            // get() copy the handle only, not the underlying 5–20 KB
            // struct (UP-15 / perf-S3). Move raw last; agent_id was
            // captured above.
            pushed_[agent_id] = std::make_shared<const RawAgentSnapshot>(std::move(raw));
        }
    }

    // Audit emission outside pushed_mu_ — AuditStore::log takes its
    // own locks; nesting would couple per-push latency to the audit
    // DB. Two emission paths:
    //   • first-push-per-agent-per-lifetime → topology.push.first
    //     (F-1 evidence chain for CC6.1/CC7.3 without per-heartbeat
    //     audit volume).
    //   • every rejection → topology.push.rejected (rare, so noise is
    //     acceptable; threshold-based audit is a follow-up).
    auto now_s = std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();
    if (!spoof_detail.empty()) {
        if (audit_store_) {
            AuditEvent ev;
            ev.timestamp = now_s;
            ev.principal = "agent:" + agent_id;
            ev.action = "topology.push.rejected";
            ev.target_type = "FleetTopology";
            ev.target_id = agent_id;
            ev.detail = spoof_detail;
            ev.result = "denied";
            audit_store_->log(ev);
        }
        return;
    }
    pushed_count_.fetch_add(1, std::memory_order_relaxed);
    if (first_push_for_this_agent && audit_store_) {
        AuditEvent ev;
        ev.timestamp = now_s;
        ev.principal = "agent:" + agent_id;
        ev.action = "topology.push.first";
        ev.target_type = "FleetTopology";
        ev.target_id = agent_id;
        ev.result = "success";
        audit_store_->log(ev);
    }
}

// PR 10 hardening — evict a deregistered agent's pushed slot.
//
// Called from AgentRegistry's remove path so a vanished agent stops
// rendering as a ghost cube (sec-M4 / UP-5) and frees its IP claims
// for re-use by a re-enrolling host.
void FleetTopologyStore::evict_pushed(const std::string& agent_id) {
    if (agent_id.empty())
        return;
    std::lock_guard plk(pushed_mu_);
    pushed_.erase(agent_id);
    for (auto it = ip_owner_.begin(); it != ip_owner_.end();) {
        if (it->second == agent_id)
            it = ip_owner_.erase(it);
        else
            ++it;
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

        // PR 10 hardening — push-staleness gate (UP-3 stuck pump).
        // An agent whose pump wedged inside tar.fleet_snapshot will
        // keep heartbeating but its last-attached snapshot's `ts` will
        // never advance. Mark the cube stale once the gap between the
        // snapshot's `ts` and wall-clock now exceeds
        // `kPushedStaleAfter`. We don't overwrite a producer-set
        // `stale=true` (the dispatch-timeout path); we only ADD the
        // age-stale flag.
        if (!m.stale && m.ts > 0) {
            const int64_t now_s = out.generated_at; // already wall-clock epoch
            const int64_t age = now_s - m.ts;
            if (age > std::chrono::duration_cast<std::chrono::seconds>(kPushedStaleAfter).count()) {
                m.stale = true;
            }
        }

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

            // Listening sockets get lifted into the per-machine
            // `listeners` array (PR 9 / UAT 2026-05-12) so the renderer
            // can draw a socket primitive on the cube top face —
            // operators want "the ports this box is exposing" to be a
            // first-class visual.
            //
            // PR 10 hardening — dual-emit during the deprecation window.
            // arch-B1 flagged that removing LISTEN rows from
            // `connections[]` is a breaking change for any consumer
            // filtering by state. We continue emitting them in
            // `connections[]` for one release alongside `listeners[]`
            // so existing MCP-driven workers and custom dashboards
            // don't break silently on minor=3. The `connections[]`
            // LISTEN rows will be removed in a future PR after one
            // full release on schema_minor=3 with a CHANGELOG
            // "Breaking" warning and an `X-Yuzu-Deprecation: ...`
            // response header pointing consumers at `listeners[]`.
            if (c.remote_addr.empty() || c.remote_port == 0) {
                if (c.state == "LISTEN" && c.local_port > 0) {
                    ListenerSocket ls;
                    ls.proto = c.proto;
                    ls.port = c.local_port;
                    ls.pid = c.pid;
                    ls.process_name = c.process_name;
                    // Preserve the bind address so the renderer can drop
                    // loopback-only listeners from the cube-surface layer
                    // (schema_minor 4) — they're not reachable from other
                    // instances, so they don't belong on the inter-host
                    // surface visual.
                    ls.local_addr = c.local_addr;
                    m.listeners.push_back(std::move(ls));
                    // Dual-emit: also keep the LISTEN row in connections[]
                    // with empty/zero remote endpoint, matching the
                    // pre-PR-9 shape. Set scope=External so the renderer's
                    // edge pass (which only draws ESTABLISHED) ignores it.
                    e.scope = EdgeScope::External;
                    m.connections.push_back(std::move(e));
                }
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

        // PR 8 / PR 10 hardening — pair each Local-scope edge with its
        // reciprocal half via an (addr,port)→(pid, index) index built
        // in one O(N) pass (perf-B2). The previous O(N²) double-loop
        // tripped on hosts with thousands of loopback connections
        // (postgres, redis, JVMs); 4096² = 16M comparisons per refill
        // was pathological once push ingestion put build_snapshot on
        // every read path.
        //
        // Identity guard via stored index — a degenerate edge whose
        // src 4-tuple equals its dst 4-tuple (kernel does not normally
        // emit this for ESTABLISHED loopback, but a synthetic / fuzzed
        // agent payload could) would otherwise self-pair with
        // dst_pid = src_pid. We compare positions in the connections
        // vector rather than pointers to avoid the pointer-stability
        // issue if we ever index this BEFORE the std::move into
        // m.connections (gov R8 cpp-expert SHOULD).
        {
            struct EndpointKey {
                std::string addr;
                int port;
                bool operator==(const EndpointKey& o) const noexcept {
                    return port == o.port && addr == o.addr;
                }
            };
            struct EndpointKeyHash {
                std::size_t operator()(const EndpointKey& k) const noexcept {
                    return std::hash<std::string>{}(k.addr) ^ (std::hash<int>{}(k.port) << 1);
                }
            };
            std::unordered_map<EndpointKey, std::pair<uint32_t, std::size_t>, EndpointKeyHash>
                by_src;
            by_src.reserve(m.connections.size());
            for (std::size_t i = 0; i < m.connections.size(); ++i) {
                const auto& e = m.connections[i];
                if (e.scope != EdgeScope::Local)
                    continue;
                by_src.emplace(EndpointKey{e.src_addr, e.src_port}, std::make_pair(e.src_pid, i));
            }
            for (std::size_t i = 0; i < m.connections.size(); ++i) {
                auto& e = m.connections[i];
                if (e.scope != EdgeScope::Local)
                    continue;
                auto it = by_src.find(EndpointKey{e.dst_addr, e.dst_port});
                if (it == by_src.end())
                    continue;
                if (it->second.second == i) // self-pair guard
                    continue;
                e.dst_pid = it->second.first;
            }
        }
        const auto before_drop = m.connections.size();
        std::erase_if(m.connections, [](const ConnectionEdge& e) {
            return e.scope == EdgeScope::Local && e.dst_pid == 0;
        });
        const auto dropped = before_drop - m.connections.size();
        if (dropped > 0) {
            // Forensic counter (gov R8 SRE/architect/security/compliance:
            // flagged by 6 separate agents as a monitoring blind spot).
            // Debug level rather than info -- half-open loopback (kernel
            // race during teardown, agent's connection cap cutting a
            // partner, TIME_WAIT-vs-ESTABLISHED snapshot) is an expected
            // source of unmatched halves, so warn would spam under normal
            // churn. Aggregate visibility comes from
            // `yuzu_viz_local_edges_dropped_total` (see counter increment
            // path below).
            spdlog::debug("FleetTopologyStore: dropped {} unmatched Local edges for agent {}",
                          dropped, m.agent_id);
            local_edges_dropped_.fetch_add(dropped, std::memory_order_relaxed);
        }

        out.machines.push_back(std::move(m));
    }

    return out;
}

} // namespace yuzu::server
