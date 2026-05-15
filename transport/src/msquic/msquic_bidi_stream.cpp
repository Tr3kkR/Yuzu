// SPDX-License-Identifier: Apache-2.0
// #376 PR 3, increment 3 — MsquicBidiStream + the per-side feeder hooks.
//
// One BidiStream impl serves both client and server sides via a
// `bool server_side` flag — only writes_done() differs:
//   - client: emits TrailingStatus(Ok) + QUIC FIN on the wire.
//   - server: no-op at the wire (the dispatcher emits the trailer with
//     the handler's RETURN status after run_bidi_handler returns).
//
// Per-call deadlines are accepted but not enforced — increment 4 wires
// them.

#include "msquic_bidi_stream.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>

#include "msquic.h"
#include "msquic_framing.hpp"
#include "msquic_internal_helpers.hpp"
#include "transport.pb.h"

namespace yuzu::transport::msquic_backend {

namespace pb = ::yuzu::transport::framing::v1;

namespace {

// ── Back-pressure thresholds (#376 PR 3 increment 3.5) ───────────────────────
//
// Production defaults: pause RECEIVE delivery once 1 MiB of decoded
// payload is buffered for the user; resume once the buffer drops to
// 256 KiB. The QUIC layer cascades flow-control credits back to the
// peer, so a chronic slow reader eventually stalls the wire-level
// sender too. Tests can override via debug::bidi_set_backpressure_thresholds.
constexpr std::size_t kDefaultBackpressureHighWatermark = 1 * 1024 * 1024;
constexpr std::size_t kDefaultBackpressureLowWatermark  = 256 * 1024;

std::atomic<std::size_t> g_high_water{kDefaultBackpressureHighWatermark};
std::atomic<std::size_t> g_low_water{kDefaultBackpressureLowWatermark};
std::atomic<std::uint64_t> g_receive_disabled_count{0};
std::atomic<std::uint64_t> g_receive_enabled_count{0};

// Owned outbound buffer; the SendBuf* is the StreamSend client context,
// freed on SEND_COMPLETE. Raw new/delete: ownership is transferred
// across the msquic C ABI — no RAII type spans the callback boundary.
struct SendBuf {
    QUIC_BUFFER quic{};
    std::string bytes;
    explicit SendBuf(std::string b) : bytes(std::move(b)) {
        quic.Buffer = reinterpret_cast<uint8_t*>(bytes.data());
        quic.Length = static_cast<uint32_t>(bytes.size());
    }
};

// Caller MUST hold state.mtx. Returns false if the stream is closed /
// cancelled or StreamSend failed. Held-lock semantics mirror the inc-2
// server-side send_frame: serialises write() against the stream
// callback's StreamClose under SHUTDOWN_COMPLETE (governance UP-1).
bool stream_send_under_lock(BidiStreamState& state, std::string framed,
                            bool fin) {
    if (state.stream_closed || state.cancelled) return false;
    const auto* api = MsQuicApi::instance().api();
    auto* sb = new SendBuf(std::move(framed));
    const QUIC_SEND_FLAGS flags =
        fin ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE;
    QUIC_STATUS st =
        api->StreamSend(state.stream, &sb->quic, 1, flags, sb);
    if (QUIC_FAILED(st)) {
        spdlog::warn("yuzu::transport[msquic][bidi]: StreamSend failed {}",
                     quic_status_hex(st));
        delete sb;
        return false;
    }
    return true;
}

}  // namespace

// ── encode_trailing_status_frame ─────────────────────────────────────────────

bool encode_trailing_status_frame(const Status& status, std::string& out) {
    pb::TrailingStatus trailer;
    trailer.set_code(
        static_cast<pb::StatusCode>(static_cast<int>(status.code)));
    trailer.set_detail(sanitise_status_detail(status.detail));
    std::string body;
    if (!trailer.SerializeToString(&body)) return false;
    return encode_frame(body, 0, out);
}

// ── Feeders ──────────────────────────────────────────────────────────────────

void feed_bidi_frame(BidiStreamState& state, std::string frame) {
    HQUIC pause_stream = nullptr;
    {
        std::lock_guard<std::mutex> lock(state.mtx);
        if (state.peer_fin || state.final_valid) {
            // Frame after FIN — wire corruption per transport.proto.
            if (!state.final_valid) {
                state.final_status = Status{
                    StatusCode::DataLoss,
                    "transport: frame received after TrailingStatus / FIN"};
                state.final_valid = true;
                state.peer_fin    = true;
            }
            state.cv.notify_all();
            return;
        }
        // One-frame lookahead: the previous pending frame is now confirmed
        // as a data frame (because another frame arrived after it). Bytes
        // already counted at the time it was first held.
        if (state.pending_frame) {
            state.inbound.push_back(std::move(*state.pending_frame));
            state.pending_frame.reset();
        }
        state.inbound_bytes += frame.size();
        state.pending_frame = std::move(frame);
        state.cv.notify_all();

        // Engage RECEIVE pause when the buffered payload crosses the
        // high-water mark. snapshot HQUIC and call StreamReceiveSetEnabled
        // OUTSIDE the lock — msquic does not synchronously re-enter our
        // callbacks but releasing the lock before the C-API call keeps the
        // discipline clean (other threads may be in write() / cancel()).
        if (!state.receive_paused &&
            state.inbound_bytes >= g_high_water.load(std::memory_order_relaxed) &&
            state.stream != nullptr && !state.stream_closed) {
            state.receive_paused = true;
            pause_stream         = state.stream;
        }
    }
    if (pause_stream != nullptr) {
        MsQuicApi::instance().api()->StreamReceiveSetEnabled(pause_stream, FALSE);
        g_receive_disabled_count.fetch_add(1, std::memory_order_relaxed);
    }
}

void feed_bidi_fin(BidiStreamState& state) {
    std::lock_guard<std::mutex> lock(state.mtx);
    if (state.peer_fin) return;  // idempotent
    state.peer_fin = true;
    if (state.pending_frame) {
        // The held-back frame is the TrailingStatus. It leaves the
        // back-pressure byte count when consumed here.
        state.inbound_bytes -= state.pending_frame->size();
        pb::TrailingStatus trailer;
        if (!trailer.ParseFromString(*state.pending_frame)) {
            state.final_status = Status{
                StatusCode::DataLoss,
                "transport: malformed TrailingStatus frame"};
        } else {
            state.final_status = Status{
                static_cast<StatusCode>(static_cast<int>(trailer.code())),
                sanitise_status_detail(trailer.detail())};
            for (const auto& [k, v] : trailer.metadata()) {
                state.trailing_metadata.emplace(
                    sanitise_status_detail(k),
                    sanitise_status_detail(v));
            }
        }
        state.pending_frame.reset();
    } else {
        state.final_status = Status{
            StatusCode::Unknown,
            "transport: peer closed without trailing status"};
    }
    state.final_valid = true;
    state.cv.notify_all();
}

void feed_bidi_error(BidiStreamState& state, Status err) {
    std::lock_guard<std::mutex> lock(state.mtx);
    if (state.final_valid) return;
    state.final_status = std::move(err);
    state.final_valid  = true;
    state.peer_fin     = true;  // unblock read()
    state.cv.notify_all();
}

// ── MsquicBidiStream ─────────────────────────────────────────────────────────

MsquicBidiStream::MsquicBidiStream(std::shared_ptr<BidiStreamState> state,
                                   bool server_side)
    : state_(std::move(state)), server_side_(server_side) {}

MsquicBidiStream::~MsquicBidiStream() {
    // Per transport.hpp: "destroying it cancels the stream if not finished."
    // "Finished" means a clean half-close (wire_fin_sent — server side
    // this is the dispatcher's post-handler trailer; client side it's
    // the writes_done() FIN) or an explicit cancel. Don't retroactively
    // ABORT a stream that already cleanly emitted its FIN.
    bool already_done;
    {
        std::lock_guard<std::mutex> lock(state_->mtx);
        already_done = state_->cancelled || state_->wire_fin_sent;
    }
    if (!already_done) cancel();
}

bool MsquicBidiStream::write(const SerializableMessage& msg,
                             std::chrono::milliseconds /*deadline*/) {
    std::string body;
    if (!msg.serialize(body)) return false;
    std::string framed;
    if (!encode_frame(body, 0, framed)) return false;
    std::lock_guard<std::mutex> lock(state_->mtx);
    if (state_->local_writes_done) return false;
    return stream_send_under_lock(*state_, std::move(framed), /*fin=*/false);
}

bool MsquicBidiStream::read(SerializableMessage& msg,
                            std::chrono::milliseconds /*deadline*/) {
    std::string frame;
    HQUIC       resume_stream = nullptr;
    {
        std::unique_lock<std::mutex> lock(state_->mtx);
        state_->cv.wait(lock, [this] {
            return !state_->inbound.empty() || state_->peer_fin ||
                   state_->cancelled;
        });
        if (state_->cancelled) return false;
        if (state_->inbound.empty()) {
            // peer_fin and nothing left to read — half-close.
            return false;
        }
        frame = std::move(state_->inbound.front());
        state_->inbound.pop_front();
        // Bytes leave the back-pressure window when the user takes them.
        state_->inbound_bytes -= frame.size();
        if (state_->receive_paused &&
            state_->inbound_bytes <=
                g_low_water.load(std::memory_order_relaxed) &&
            state_->stream != nullptr && !state_->stream_closed) {
            state_->receive_paused = false;
            resume_stream          = state_->stream;
        }
    }
    if (resume_stream != nullptr) {
        MsQuicApi::instance().api()->StreamReceiveSetEnabled(resume_stream, TRUE);
        g_receive_enabled_count.fetch_add(1, std::memory_order_relaxed);
    }
    return msg.parse(frame);
}

void MsquicBidiStream::writes_done() {
    if (server_side_) {
        // Server-side writes_done is a no-op at the wire — the
        // dispatcher emits the TrailingStatus + FIN with the handler's
        // RETURN status after run_bidi_handler returns. The flag here
        // makes subsequent write() return false (transport.hpp says
        // write is invalid post-writes_done).
        std::lock_guard<std::mutex> lock(state_->mtx);
        state_->local_writes_done = true;
        return;
    }
    // Client side: emit a TrailingStatus(Ok) frame + FIN. The client has
    // no application-level RPC status to report — Ok signals "done
    // sending" per transport.proto.
    std::string framed;
    if (!encode_trailing_status_frame(Status{StatusCode::Ok, ""}, framed)) {
        // Vanishingly unlikely (trivial protobuf). Abort the stream.
        std::lock_guard<std::mutex> lock(state_->mtx);
        if (!state_->stream_closed) {
            MsQuicApi::instance().api()->StreamShutdown(
                state_->stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        }
        return;
    }
    std::lock_guard<std::mutex> lock(state_->mtx);
    if (state_->local_writes_done) return;  // idempotent
    state_->local_writes_done = true;
    if (stream_send_under_lock(*state_, std::move(framed), /*fin=*/true)) {
        state_->wire_fin_sent = true;
    }
}

// ── send_server_trailer_and_fin ──────────────────────────────────────────────
//
// The server-side dispatcher (run_bidi_handler in msquic_listener.cpp)
// calls this after the handler returns to emit the TrailingStatus +
// QUIC FIN with the handler's RETURN status. Sets wire_fin_sent so the
// MsquicBidiStream destructor (which runs next) does not ABORT the
// cleanly-half-closed stream.

void send_server_trailer_and_fin(BidiStreamState& state, const Status& status) {
    std::string framed;
    if (!encode_trailing_status_frame(status, framed)) {
        std::lock_guard<std::mutex> lock(state.mtx);
        if (!state.stream_closed && !state.cancelled) {
            MsQuicApi::instance().api()->StreamShutdown(
                state.stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        }
        return;
    }
    std::lock_guard<std::mutex> lock(state.mtx);
    if (state.wire_fin_sent || state.cancelled || state.stream_closed) return;
    state.local_writes_done = true;
    if (stream_send_under_lock(state, std::move(framed), /*fin=*/true)) {
        state.wire_fin_sent = true;
    }
}

Status MsquicBidiStream::final_status() {
    std::unique_lock<std::mutex> lock(state_->mtx);
    state_->cv.wait(lock, [this] { return state_->final_valid; });
    return state_->final_status;
}

const std::map<std::string, std::string>&
MsquicBidiStream::trailing_metadata() const {
    return state_->trailing_metadata;
}

void MsquicBidiStream::cancel() {
    bool need_shutdown;
    {
        std::lock_guard<std::mutex> lock(state_->mtx);
        if (state_->cancelled) return;  // idempotent
        state_->cancelled = true;
        need_shutdown     = !state_->stream_closed;
        state_->cv.notify_all();
    }
    if (need_shutdown) {
        MsQuicApi::instance().api()->StreamShutdown(
            state_->stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }
}

// ── debug:: probes (test-only) ───────────────────────────────────────────────

namespace debug {

std::uint64_t bidi_receive_disabled_count() {
    return g_receive_disabled_count.load(std::memory_order_relaxed);
}

std::uint64_t bidi_receive_enabled_count() {
    return g_receive_enabled_count.load(std::memory_order_relaxed);
}

void bidi_reset_backpressure_counters() {
    g_receive_disabled_count.store(0, std::memory_order_relaxed);
    g_receive_enabled_count.store(0, std::memory_order_relaxed);
}

void bidi_set_backpressure_thresholds(std::size_t high_bytes,
                                      std::size_t low_bytes) {
    g_high_water.store(high_bytes, std::memory_order_relaxed);
    g_low_water.store(low_bytes, std::memory_order_relaxed);
}

void bidi_reset_backpressure_thresholds() {
    g_high_water.store(kDefaultBackpressureHighWatermark,
                       std::memory_order_relaxed);
    g_low_water.store(kDefaultBackpressureLowWatermark,
                      std::memory_order_relaxed);
}

}  // namespace debug

}  // namespace yuzu::transport::msquic_backend
