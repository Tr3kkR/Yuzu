/**
 * es_client.cpp -- see yuzu/agent/es_client.hpp.
 */
#include <yuzu/agent/es_client.hpp>

namespace yuzu::agent {

std::uint64_t es_seq_gap(std::uint64_t last_seq, std::uint64_t seq) noexcept {
    // Only a strict forward jump is a kernel drop; equal/decreasing seq (a client
    // re-create resets the per-type counter) yields 0 rather than underflowing.
    return seq > last_seq + 1 ? seq - last_seq - 1 : 0;
}

} // namespace yuzu::agent
