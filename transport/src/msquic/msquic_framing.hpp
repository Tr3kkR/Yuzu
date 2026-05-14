// SPDX-License-Identifier: Apache-2.0
// QUIC length-prefix framing codec.
//
// A QUIC bidirectional stream is a raw, ordered byte stream — unlike
// gRPC's HTTP/2 transport it carries no message-framing layer. The
// msquic backend frames each protobuf message with a 4-byte big-endian
// length prefix (transport.hpp wire-protocol invariant 1):
//
//   [ uint32 BE length ][ ... length bytes of protobuf payload ... ]
//
// This translation unit has ZERO dependency on the msquic C library or
// on protobuf — it operates on opaque byte buffers. It is therefore
// compiled unconditionally into yuzu_transport (not gated behind the
// `transport` meson option) so the codec is testable on every build
// configuration.
//
// #376 PR 3, increment 1.

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <string_view>

#include "yuzu/transport/transport.hpp"  // kDefaultMaxFrameSize, StatusCode

namespace yuzu::transport::msquic_backend {

// Encode `payload` as a single framed message into `out`. `out` is
// OVERWRITTEN (not appended) — one call produces exactly one self-
// contained frame, which becomes one owned QUIC send buffer.
//
// `max_frame` is the application frame-size cap; 0 means
// kDefaultMaxFrameSize. Returns false if `payload` exceeds the effective
// cap — the caller maps that to StatusCode::ResourceExhausted before any
// bytes reach the wire.
bool encode_frame(std::string_view payload, std::size_t max_frame,
                  std::string& out);

// Stateful inbound decoder. QUIC RECEIVE events deliver bytes in
// arbitrary chunks — a chunk may split the 4-byte length prefix, carry a
// partial payload, or pack several whole frames together. feed()
// accumulates raw bytes; next_frame() pops fully-assembled frames in
// arrival order.
//
// Frame-size enforcement: the moment all 4 length-prefix bytes are in
// hand, the declared length is compared against the cap BEFORE any
// payload buffer is sized to that (peer-controlled) value. An over-cap
// prefix puts the decoder into a terminal error state — feed() returns
// the error status and keeps returning it on every subsequent call, and
// no further frames are produced. The msquic stream layer maps that to
// stream cancellation + an audit event.
class FrameDecoder {
public:
    // `max_frame` == 0 -> kDefaultMaxFrameSize.
    explicit FrameDecoder(std::size_t max_frame = 0)
        : max_frame_(max_frame ? max_frame : kDefaultMaxFrameSize) {}

    // Feed raw bytes received from the wire. Returns StatusCode::Ok on a
    // clean parse, or StatusCode::ResourceExhausted if a length prefix
    // declares a frame larger than the cap. The error is sticky.
    StatusCode feed(std::string_view bytes);

    // Pop the next fully-assembled frame, or std::nullopt if none is
    // ready (or the decoder has errored).
    std::optional<std::string> next_frame();

    // True if bytes have been buffered toward a frame that has not yet
    // fully arrived.
    bool has_pending_partial() const noexcept { return !buffer_.empty(); }

private:
    std::size_t             max_frame_;
    std::string             buffer_;   // unconsumed wire bytes
    std::deque<std::string> ready_;    // fully-assembled frames, FIFO
    StatusCode              error_ = StatusCode::Ok;
};

}  // namespace yuzu::transport::msquic_backend
