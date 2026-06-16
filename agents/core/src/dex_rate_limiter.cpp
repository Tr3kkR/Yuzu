#include <yuzu/agent/dex_rate_limiter.hpp>

#include <yuzu/agent/dex_signal_catalog.hpp> // dex_signal_catalog, SignalSpec

namespace yuzu::agent {

int dex_obs_cap_per_hour(std::string_view obs_type) {
    for (const SignalSpec& spec : dex_signal_catalog())
        if (obs_type == spec.obs_type) // first match wins (same obs_type → same cap)
            return spec.max_per_hour;
    return 60; // SignalSpec's own default for an uncatalogued type
}

RateDecision DexRateLimiter::check(const std::string& obs_type, std::int64_t timestamp_unix) {
    const std::int64_t hour = timestamp_unix / 3600;
    Bucket& b = buckets_[obs_type];
    if (b.hour != hour) { // new window (or first observation of this type) — reset + cache cap
        b.hour = hour;
        b.count = 0;
        b.warned = false;
        b.cap = dex_obs_cap_per_hour(obs_type);
    }
    if (b.count < b.cap) {
        ++b.count; // saturates at cap — never increments past it, so no overflow under a storm
        return RateDecision::Emit;
    }
    if (!b.warned) {
        b.warned = true;
        return RateDecision::DropAndWarn; // first drop of the hour — caller logs once
    }
    return RateDecision::Drop;
}

} // namespace yuzu::agent
