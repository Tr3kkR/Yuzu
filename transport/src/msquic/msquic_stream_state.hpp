// SPDX-License-Identifier: Apache-2.0
// BidiStreamState — the per-bidi-stream blocking-bridge control block,
// shared by the client and server sides of the msquic backend.
//
// msquic is callback-driven; the yuzu BidiStream surface
// (read/write/writes_done/final_status/cancel) is synchronous. The
// synchronous calls park on `cv`; the owning per-stream context's msquic
// RECEIVE callback decodes frames, routes them in here, and notifies.
//
// The FrameDecoder itself lives in the per-side per-stream context
// (ServerStreamCall on the server, ClientBidiCall on the client), NOT
// here — this struct is only the post-decode frame queue + lifecycle
// flags + the synthesised peer trailing status.
//
// #376 PR 3, increment 3.

#pragma once

#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>

#include "msquic.h"

#include "yuzu/transport/transport.hpp"

namespace yuzu::transport::msquic_backend {

// Wire invariant (transport.proto / governance arch-SHOULD): the LAST
// frame before the peer's FIN is the TrailingStatus; every earlier frame
// is a data frame. The feeder uses ONE-FRAME LOOKAHEAD — `pending_frame`
// holds the most recently decoded frame until either the next frame
// confirms it as data (it moves to `inbound`) or the peer FIN confirms
// it as the trailer. Receiving a frame after the trailer, or a second
// trailer, is wire corruption -> DataLoss.
struct BidiStreamState {
    HQUIC                          stream = nullptr;
    std::weak_ptr<BidiStreamState> self;

    std::mutex              mtx;
    std::condition_variable cv;

    // Decoded DATA frames ready for read(), FIFO. `pending_frame` is the
    // one-frame lookahead buffer (see the wire-invariant note above).
    std::deque<std::string>    inbound;
    std::optional<std::string> pending_frame;

    bool peer_fin          = false;  // peer sent its TrailingStatus + FIN
    bool cancelled         = false;  // cancel(), deadline, or transport error
    // local_writes_done: the user (handler / channel caller) called
    // writes_done(). write() returns false thereafter. Server-side this
    // is purely a user-flag — the wire-level FIN is sent by the
    // dispatcher (see wire_fin_sent below).
    bool local_writes_done = false;
    // wire_fin_sent: a StreamSend with QUIC_SEND_FLAG_FIN succeeded.
    // ~MsquicBidiStream uses this (not local_writes_done) to decide
    // whether to ABORT on dtor — destroying a cleanly half-closed stream
    // must not retroactively abort it. Set by send_server_trailer_and_fin
    // (server) and by client-side writes_done() after a successful FIN send.
    bool wire_fin_sent     = false;
    // The msquic stream HQUIC has been closed (SHUTDOWN_COMPLETE +
    // StreamClose). All further StreamSend/StreamShutdown is undefined —
    // write() / cancel() must no-op. Mirrors the inc-2 ServerStreamCall
    // UP-1/CH-1 fix for the bidi path. Set under `mtx` by the per-side
    // SHUTDOWN_COMPLETE handler, paired with the StreamClose call.
    bool stream_closed     = false;

    // Synthesised once the peer's TrailingStatus frame is decoded (or the
    // stream broke). final_valid implies peer_fin; final_status() blocks
    // on it. trailing_metadata is scrubbed at the inbound boundary.
    Status                             final_status;
    std::map<std::string, std::string> trailing_metadata;
    bool                               final_valid = false;
};

}  // namespace yuzu::transport::msquic_backend
