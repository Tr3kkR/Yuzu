// SPDX-License-Identifier: Apache-2.0
// MsquicBidiStream — the msquic backend implementation of
// yuzu::transport::BidiStream, shared by the client and server sides.
//
// One class implements both sides over a `shared_ptr<BidiStreamState>`;
// only writes_done() differs:
//   - client: emits a TrailingStatus(Ok) frame + QUIC FIN.
//   - server: NO-OP at the wire — the dispatcher emits the trailer with
//     the handler's RETURN status after run_bidi_handler returns. This
//     mirrors the gRPC backend's server-side BidiStreamAdapter.
//
// The msquic RECEIVE callback on each side decodes frames and calls
// feed_bidi_frame() / feed_bidi_fin() / feed_bidi_error() to route them
// into the BidiStreamState — `read()` then pops from there.
//
// #376 PR 3, increment 3.

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "msquic_stream_state.hpp"
#include "yuzu/transport/transport.hpp"

namespace yuzu::transport::msquic_backend {

class MsquicBidiStream final : public BidiStream {
public:
    MsquicBidiStream(std::shared_ptr<BidiStreamState> state, bool server_side);
    ~MsquicBidiStream() override;

    MsquicBidiStream(const MsquicBidiStream&)            = delete;
    MsquicBidiStream& operator=(const MsquicBidiStream&) = delete;

    // Per the transport.hpp BidiStream contract. The deadline parameter
    // is plumbed through but not yet enforced — per-call deadlines land
    // in increment 4.
    bool write(const SerializableMessage& msg,
               std::chrono::milliseconds deadline =
                   std::chrono::milliseconds::zero()) override;
    bool read(SerializableMessage& msg,
              std::chrono::milliseconds deadline =
                  std::chrono::milliseconds::zero()) override;
    void writes_done() override;
    Status final_status() override;
    const std::map<std::string, std::string>& trailing_metadata() const override;
    void cancel() override;

private:
    std::shared_ptr<BidiStreamState> state_;
    bool                             server_side_;
};

// ── Feeder hooks (shared by the client and server msquic callbacks) ──────────
//
// One-frame-lookahead routing of decoded frames into a BidiStreamState.
// Call sequence per stream:
//   feed_bidi_frame(state, frame)  — once per data frame the decoder emits
//   feed_bidi_fin(state)           — when the peer FIN is observed
//   feed_bidi_error(state, status) — on transport/decoder error (terminal)
//
// Wire invariant (transport.proto / governance arch-SHOULD):
//   - The most recent decoded frame is held in `state.pending_frame`.
//   - The next frame promotes the previous one to `state.inbound`
//     (confirmed data).
//   - feed_bidi_fin parses `pending_frame` as the TrailingStatus; if
//     `pending_frame` is empty at FIN, synthesises Unknown "peer closed
//     without trailing status".
//   - A frame after FIN, or two TrailingStatus frames, is DataLoss
//     (caller signals this via feed_bidi_error).

void feed_bidi_frame(BidiStreamState& state, std::string frame);
void feed_bidi_fin(BidiStreamState& state);
void feed_bidi_error(BidiStreamState& state, Status err);

// Encode a TrailingStatus frame for the client-side writes_done() path,
// or for the server dispatcher's post-handler emission. Returns false
// only on the (vanishingly unlikely) protobuf serialise / oversize
// failure — caller maps to a stream abort.
bool encode_trailing_status_frame(const Status& status, std::string& out);

// Server-side dispatcher: emit a TrailingStatus frame + QUIC FIN with
// the handler's RETURN status. Called by run_bidi_handler AFTER the
// handler returns and BEFORE the MsquicBidiStream destructs (so the
// dtor sees `wire_fin_sent` and skips the abort path). Idempotent w.r.t.
// already-cancelled / already-closed streams (no-op).
void send_server_trailer_and_fin(BidiStreamState& state, const Status& status);

// ── Test-only probes for back-pressure (#376 PR 3 increment 3.5) ─────────────
//
// The feeder + read() path engages msquic flow control via
// StreamReceiveSetEnabled when `inbound_bytes` crosses the high-water
// mark and re-enables once it drops to the low-water mark. The default
// thresholds are sized for production traffic (1 MiB / 256 KiB); tests
// can lower them to exercise the path without sending megabytes of
// payload. Counters are process-global and increment monotonically; tests
// MUST call `bidi_reset_backpressure_counters()` at start to avoid
// inheriting counts from prior cases.
namespace debug {
std::uint64_t bidi_receive_disabled_count();
std::uint64_t bidi_receive_enabled_count();
void          bidi_reset_backpressure_counters();
void          bidi_set_backpressure_thresholds(std::size_t high_bytes,
                                               std::size_t low_bytes);
void          bidi_reset_backpressure_thresholds();
}  // namespace debug

}  // namespace yuzu::transport::msquic_backend
