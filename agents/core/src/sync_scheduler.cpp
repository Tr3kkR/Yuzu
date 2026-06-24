#include "sync_scheduler.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <optional>

namespace yuzu::agent {

namespace {

// FNV-1a 64-bit over a string — deterministic across platforms and process
// runs (unlike std::hash), so the per-(agent,source) phase offset is stable
// across reboots (ADR-0016 §3): the fleet keeps a uniform, reproducible spread.
std::uint64_t fnv1a(const std::string& s) {
    std::uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h;
}

// Smallest T > now with (T mod interval) == offset (the next phase-aligned slot).
std::int64_t next_slot(std::int64_t now, std::int64_t interval, std::int64_t offset) {
    if (interval <= 0)
        return now + 1;
    std::int64_t base = now - (now % interval) + offset;
    if (base <= now)
        base += interval;
    return base;
}

} // namespace

SyncScheduler::SyncScheduler(std::string agent_id, KvGetFn kv_get, KvSetFn kv_set, SenderFn sender)
    : agent_id_(std::move(agent_id)), kv_get_(std::move(kv_get)), kv_set_(std::move(kv_set)),
      sender_(std::move(sender)) {}

void SyncScheduler::add_source(SyncSource src) {
    sources_.push_back(std::move(src));
    states_.emplace_back();
}

std::string SyncScheduler::kv_key(const std::string& source, const char* field) const {
    return "sync." + source + "." + field;
}

std::int64_t SyncScheduler::phase_offset(const std::string& source, std::int64_t interval) const {
    if (interval <= 0)
        return 0;
    return static_cast<std::int64_t>(fnv1a(agent_id_ + ":" + source) %
                                     static_cast<std::uint64_t>(interval));
}

SyncScheduler::State& SyncScheduler::load_state(const SyncSource& src, std::int64_t now_secs) {
    State& st = states_[static_cast<std::size_t>(&src - sources_.data())];
    if (st.loaded)
        return st;

    const std::string nf = kv_get_(kv_key(src.name, "next_fire"));
    if (nf.empty()) {
        // First run: catch up soon, jittered by a stable per-(agent,source)
        // offset in [0, kStartupJitterWindow) so a mass-enroll does not herd.
        const std::int64_t jitter = static_cast<std::int64_t>(
            fnv1a(agent_id_ + ":startup:" + src.name) %
            static_cast<std::uint64_t>(kStartupJitterWindow.count()));
        st.next_fire = now_secs + jitter;
        st.last_full = 0;
        st.last_hash.clear();
        st.force_full = false;
        save_state(src, st);
    } else {
        st.next_fire = std::strtoll(nf.c_str(), nullptr, 10);
        st.last_full = std::strtoll(kv_get_(kv_key(src.name, "last_full")).c_str(), nullptr, 10);
        st.last_hash = kv_get_(kv_key(src.name, "last_hash"));
        st.force_full = kv_get_(kv_key(src.name, "force_full")) == "1";
    }
    st.loaded = true;
    return st;
}

void SyncScheduler::save_state(const SyncSource& src, const State& st) {
    kv_set_(kv_key(src.name, "next_fire"), std::to_string(st.next_fire));
    kv_set_(kv_key(src.name, "last_full"), std::to_string(st.last_full));
    kv_set_(kv_key(src.name, "last_hash"), st.last_hash);
    kv_set_(kv_key(src.name, "force_full"), st.force_full ? "1" : "0");
}

std::chrono::seconds SyncScheduler::tick(std::int64_t now_secs) {
    // Gather every due source's hash (always) + blob (only when sending full).
    std::vector<std::pair<std::string, std::string>> hashes;
    std::vector<std::pair<std::string, std::string>> blobs;
    std::vector<std::size_t> due_idx;
    std::vector<std::string> due_hash; // current hash per due source (index-aligned)
    std::vector<bool> sent_full;

    for (std::size_t i = 0; i < sources_.size(); ++i) {
        const SyncSource& src = sources_[i];
        State& st = load_state(src, now_secs);
        if (now_secs < st.next_fire)
            continue;

        auto collected = src.collect ? src.collect() : std::nullopt;
        if (!collected) {
            // Source unavailable this cycle (e.g. backing plugin not loaded).
            // Skip + retry next interval; leave last_hash untouched.
            spdlog::debug("sync: source '{}' collect returned nothing — skipping", src.name);
            st.next_fire = now_secs + src.interval.count();
            save_state(src, st);
            continue;
        }
        const std::string& blob = collected->first;
        const std::string& hash = collected->second;

        const bool floor_due =
            (now_secs - st.last_full) >= static_cast<std::int64_t>(kFullFloor.count());
        const bool full = st.force_full || st.last_hash.empty() || floor_due || hash != st.last_hash;

        hashes.emplace_back(src.name, hash);
        if (full)
            blobs.emplace_back(src.name, blob);

        due_idx.push_back(i);
        due_hash.push_back(hash);
        sent_full.push_back(full);
    }

    if (!due_idx.empty()) {
        auto need_full = sender_ ? sender_(hashes, blobs) : std::nullopt;
        if (!need_full) {
            // RPC failed — do NOT advance state; the next pass retries. The
            // clamped sleep below throttles a persistent-failure loop.
            spdlog::debug("sync: ReportInventory RPC failed — {} source(s) will retry",
                          due_idx.size());
        } else {
            const auto& nf = *need_full;
            const auto needs_full = [&](const std::string& n) {
                return std::find(nf.begin(), nf.end(), n) != nf.end();
            };
            for (std::size_t k = 0; k < due_idx.size(); ++k) {
                const SyncSource& src = sources_[due_idx[k]];
                State& st = states_[due_idx[k]];
                if (needs_full(src.name)) {
                    // Server could not materialise from a hash-only report
                    // (cold cache / drift): resend full promptly, but spread the
                    // resend by a stable per-(agent,source) offset so a fleet-wide
                    // cold cache doesn't stampede full payloads at once.
                    st.force_full = true;
                    const std::int64_t nf_jitter = static_cast<std::int64_t>(
                        fnv1a(agent_id_ + ":needfull:" + src.name) %
                        static_cast<std::uint64_t>(kNeedFullJitterWindow.count()));
                    st.next_fire = now_secs + kMinTickSeconds.count() + nf_jitter;
                } else {
                    st.last_hash = due_hash[k];
                    st.force_full = false;
                    if (sent_full[k])
                        st.last_full = now_secs;
                    st.next_fire = next_slot(now_secs, src.interval.count(),
                                             phase_offset(src.name, src.interval.count()));
                }
                save_state(src, st);
            }
        }
    }

    // Sleep until the soonest next_fire, clamped.
    std::int64_t soonest = now_secs + kMaxTickSeconds.count();
    for (std::size_t i = 0; i < sources_.size(); ++i) {
        if (states_[i].loaded)
            soonest = std::min(soonest, states_[i].next_fire);
    }
    std::int64_t sleep_for = soonest - now_secs;
    sleep_for = std::clamp<std::int64_t>(sleep_for, kMinTickSeconds.count(), kMaxTickSeconds.count());
    return std::chrono::seconds{sleep_for};
}

} // namespace yuzu::agent
