#include "dex_macos_perf.hpp"

#include <limits>

namespace yuzu::agent::macos {

namespace {

// Saturating uint64 multiply: never wraps past UINT64_MAX.
std::uint64_t sat_mul(std::uint64_t a, std::uint64_t b) {
    if (a == 0 || b == 0)
        return 0;
    if (a > std::numeric_limits<std::uint64_t>::max() / b)
        return std::numeric_limits<std::uint64_t>::max();
    return a * b;
}

} // namespace

std::uint64_t mach_abs_to_100ns(std::uint64_t t, std::uint32_t numer, std::uint32_t denom) noexcept {
    if (denom == 0)
        return 0; // corrupt timebase — never divide by zero
    // t*numer saturates first (it can overflow 64 bits well before the final /100);
    // the two divides then reduce ticks -> ns -> 100ns, matching ProcCounter::cpu_100ns's unit.
    const std::uint64_t ns = sat_mul(t, static_cast<std::uint64_t>(numer)) / denom;
    return ns / 100;
}

} // namespace yuzu::agent::macos
