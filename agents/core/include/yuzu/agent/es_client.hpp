#pragma once

/**
 * es_client.hpp -- shared, pure Endpoint Security helpers.
 *
 * es_seq_gap() (and, in a follow-up commit, es_stream_is_stalled()) are
 * lifted from TAR's tar_proc_es.cpp (A0, macOS Spark/Reflex/DEX programme)
 * into agent-core so a future shared ES client (a later slice) and TAR's own
 * process collector both consume ONE copy. Pure integer arithmetic -- no ES
 * headers, no platform API -- so, like every other pure-decision-code header
 * in this tree, this compiles and is unit-tested on every host even though
 * only a macOS/YUZU_HAVE_ENDPOINT_SECURITY caller exists today.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>

namespace yuzu::agent {

/// Count kernel-side ES drops from a seq_num gap: only a strict forward jump
/// counts (a client re-create resets the per-type counter, which must never
/// underflow into a huge bogus count).
[[nodiscard]] YUZU_EXPORT std::uint64_t es_seq_gap(std::uint64_t last, std::uint64_t seq) noexcept;

} // namespace yuzu::agent
