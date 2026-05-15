// SPDX-License-Identifier: Apache-2.0
// #376 PR 3, increment 3 — MsquicChannel: client connection establishment,
// synchronous unary RPC, and bidi streams (the bidi BidiStream impl
// itself is the shared MsquicBidiStream from msquic_bidi_stream.hpp).
//
// Out of scope for increment 3: per-call deadlines (increment 4), mTLS /
// server-cert verification (increment 5 — honours verify_peer=false
// only), the metric sink (increment 6).

#include "msquic_channel.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>

#include "msquic_bidi_stream.hpp"
#include "msquic_framing.hpp"
#include "msquic_internal_helpers.hpp"
#include "msquic_stream_state.hpp"
#include "transport.pb.h"  // HandshakeHello, TrailingStatus
#include "yuzu/secure_zero.hpp"

namespace yuzu::transport::msquic_backend {

namespace pb = ::yuzu::transport::framing::v1;
using namespace std::chrono_literals;

// ── Per-stream client-side unary call state ──────────────────────────────────

struct ClientUnaryCall {
    MsquicChannel* channel = nullptr;
    HQUIC          stream  = nullptr;
    std::weak_ptr<ClientUnaryCall> self;

    FrameDecoder             decoder;
    std::mutex               mtx;
    std::condition_variable  cv;
    std::vector<std::string> frames;            // decoded inbound frames
    bool                     done = false;
    Status                   transport_error;   // non-Ok if the stream broke

    // True only when the peer half-closed cleanly (RECEIVE-with-FIN or
    // PEER_SEND_SHUTDOWN). A stream that ended by abort / connection
    // drop / mid-response crash leaves this false — and the frame
    // sequence is then indeterminate, so unary() must not interpret it
    // as a complete server message (governance UP-14 / CH-3).
    bool                     peer_clean_fin = false;

    explicit ClientUnaryCall(std::size_t max_frame) : decoder(max_frame) {}
};

// ── Per-stream client-side bidi call state ───────────────────────────────────
//
// Owns the FrameDecoder and the channel-side handle bookkeeping; the
// blocking-bridge state (frame queue, cv, peer_fin, etc.) lives in the
// shared BidiStreamState which is also held by the MsquicBidiStream
// returned to the caller. The msquic stream callback recovers this raw
// pointer from the stream's context, decodes RECEIVE bytes here, and
// routes frames into `state` via feed_bidi_frame / feed_bidi_fin.

struct ClientBidiCall {
    MsquicChannel*                channel = nullptr;
    HQUIC                         stream  = nullptr;
    std::weak_ptr<ClientBidiCall> self;

    FrameDecoder                  decoder;
    std::shared_ptr<BidiStreamState> state;
    std::string                   method;  // for metric_sink labels

    explicit ClientBidiCall(std::size_t max_frame) : decoder(max_frame) {}
};

namespace {

// Owned outbound buffer; the SendBuf* is the StreamSend client context,
// freed on SEND_COMPLETE. Raw new/delete: ownership is transferred
// across the msquic C ABI — the client context is a void* msquic hands
// back at SEND_COMPLETE, which no RAII type spans.
struct SendBuf {
    QUIC_BUFFER quic{};
    std::string bytes;
    explicit SendBuf(std::string b) : bytes(std::move(b)) {
        quic.Buffer = reinterpret_cast<uint8_t*>(bytes.data());
        quic.Length = static_cast<uint32_t>(bytes.size());
    }
};

// Send one already-framed payload. `fin` half-closes the send direction
// after this buffer. On failure the SendBuf is freed here; on success it
// is freed in the stream's SEND_COMPLETE handler. Optional metric sink
// fires on_bytes_sent("msquic", payload size) on a successful send.
bool send_framed(HQUIC stream, std::string framed, bool fin,
                 const std::shared_ptr<TransportMetricSink>& sink = nullptr) {
    const auto* api = MsQuicApi::instance().api();
    const std::size_t bytes = framed.size();
    auto* sb = new SendBuf(std::move(framed));
    const QUIC_SEND_FLAGS flags =
        fin ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE;
    QUIC_STATUS st = api->StreamSend(stream, &sb->quic, 1, flags, sb);
    if (QUIC_FAILED(st)) {
        spdlog::warn("yuzu::transport[msquic]: client StreamSend failed {}",
                     quic_status_hex(st));
        delete sb;
        return false;
    }
    safe_sink_invoke(sink, [bytes](auto& s) { s.on_bytes_sent("msquic", bytes); });
    return true;
}

// Mark a call complete and wake unary(). `clean_fin` records whether the
// peer half-closed cleanly — only the RECEIVE-with-FIN and
// PEER_SEND_SHUTDOWN paths pass true (governance UP-14 / CH-3).
void finish_call(ClientUnaryCall* call, Status error,
                 bool clean_fin = false) {
    {
        std::lock_guard<std::mutex> lock(call->mtx);
        if (call->done) return;
        if (clean_fin) call->peer_clean_fin = true;
        if (!error.ok() && call->transport_error.ok()) {
            call->transport_error = std::move(error);
        }
        call->done = true;
    }
    call->cv.notify_all();
}

}  // namespace

// ── msquic client callback trampolines ───────────────────────────────────────

QUIC_STATUS QUIC_API msquic_client_stream_callback(HQUIC stream, void* ctx,
                                                   QUIC_STREAM_EVENT* ev) {
    auto* call = static_cast<ClientUnaryCall*>(ctx);
    switch (ev->Type) {
        case QUIC_STREAM_EVENT_RECEIVE: {
            bool fin = (ev->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) != 0;
            StatusCode sc = StatusCode::Ok;
            std::size_t total_bytes = 0;
            for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i) {
                total_bytes += ev->RECEIVE.Buffers[i].Length;
            }
            if (total_bytes != 0 && call->channel) {
                safe_sink_invoke(call->channel->metric_sink_, [&](auto& s) {
                    s.on_bytes_received("msquic", total_bytes);
                });
            }
            {
                std::lock_guard<std::mutex> lock(call->mtx);
                // Ignore a RECEIVE that arrives after the call already
                // completed — unary() has moved-from call->frames
                // (governance UP-17).
                if (call->done) return QUIC_STATUS_SUCCESS;
                for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i) {
                    const auto& b = ev->RECEIVE.Buffers[i];
                    sc = call->decoder.feed(std::string_view{
                        reinterpret_cast<const char*>(b.Buffer), b.Length});
                    if (sc != StatusCode::Ok) break;
                }
                if (sc == StatusCode::Ok) {
                    for (;;) {
                        auto f = call->decoder.next_frame();
                        if (!f) break;
                        call->frames.push_back(std::move(*f));
                    }
                }
            }
            if (sc != StatusCode::Ok) {
                MsQuicApi::instance().api()->StreamShutdown(
                    stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
                finish_call(call,
                            Status{StatusCode::DataLoss,
                                   "transport: inbound framing error"});
            } else if (fin) {
                // RECEIVE-with-FIN is a clean peer half-close.
                finish_call(call, Status{}, /*clean_fin=*/true);
            }
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            // Clean peer half-close.
            finish_call(call, Status{}, /*clean_fin=*/true);
            return QUIC_STATUS_SUCCESS;

        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            finish_call(call, Status{StatusCode::Cancelled,
                                     "transport: peer aborted the stream"});
            return QUIC_STATUS_SUCCESS;

        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            delete static_cast<SendBuf*>(ev->SEND_COMPLETE.ClientContext);
            return QUIC_STATUS_SUCCESS;

        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
            // Whatever the cause, the stream is over. If unary() has not
            // been woken yet, wake it — it will synthesise an Unknown
            // trailing status from the (empty) frame list.
            finish_call(call, Status{});
            MsquicChannel* channel = call->channel;
            MsQuicApi::instance().api()->StreamClose(stream);
            channel->untrack_call(stream);
            return QUIC_STATUS_SUCCESS;
        }

        default:
            return QUIC_STATUS_SUCCESS;
    }
}

// ── Client-side BIDI stream callback ─────────────────────────────────────────
//
// Decodes RECEIVE bytes and routes them into the shared BidiStreamState
// via the feed_bidi_* helpers. Mirrors msquic_client_stream_callback
// (unary) but talks to a BidiStreamState instead of a ClientUnaryCall's
// frames vector — and uses one-frame lookahead for trailing-status
// detection inside the feeders.

QUIC_STATUS QUIC_API msquic_client_bidi_stream_callback(
    HQUIC stream, void* ctx, QUIC_STREAM_EVENT* ev) {
    auto* call = static_cast<ClientBidiCall*>(ctx);
    switch (ev->Type) {
        case QUIC_STREAM_EVENT_RECEIVE: {
            const bool fin =
                (ev->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) != 0;
            StatusCode sc = StatusCode::Ok;
            std::size_t total_bytes = 0;
            for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i) {
                total_bytes += ev->RECEIVE.Buffers[i].Length;
            }
            if (total_bytes != 0 && call->channel) {
                safe_sink_invoke(call->channel->metric_sink_, [&](auto& s) {
                    s.on_bytes_received("msquic", total_bytes);
                });
            }
            for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i) {
                const auto& b = ev->RECEIVE.Buffers[i];
                sc = call->decoder.feed(std::string_view{
                    reinterpret_cast<const char*>(b.Buffer), b.Length});
                if (sc != StatusCode::Ok) break;
            }
            if (sc != StatusCode::Ok) {
                MsQuicApi::instance().api()->StreamShutdown(
                    stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
                feed_bidi_error(*call->state,
                                Status{StatusCode::DataLoss,
                                       "transport: inbound framing error"});
                return QUIC_STATUS_SUCCESS;
            }
            for (;;) {
                auto f = call->decoder.next_frame();
                if (!f) break;
                feed_bidi_frame(*call->state, std::move(*f));
            }
            if (fin) feed_bidi_fin(*call->state);
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            feed_bidi_fin(*call->state);
            return QUIC_STATUS_SUCCESS;

        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            feed_bidi_error(*call->state,
                            Status{StatusCode::Cancelled,
                                   "transport: peer aborted the stream"});
            return QUIC_STATUS_SUCCESS;

        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            delete static_cast<SendBuf*>(ev->SEND_COMPLETE.ClientContext);
            return QUIC_STATUS_SUCCESS;

        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
            MsquicChannel* channel = call->channel;
            // Mirror the server-side B2 fix: serialise the StreamClose
            // with any in-flight write() via state->stream_closed under
            // state->mtx (governance UP-1 / CH-1 — the bidi side).
            {
                std::lock_guard<std::mutex> lock(call->state->mtx);
                call->state->stream_closed = true;
                MsQuicApi::instance().api()->StreamClose(stream);
            }
            // Synthesise a final status if the peer never delivered a
            // clean trailer (otherwise final_status() blocks forever).
            // No-op if final_valid was already set by feed_bidi_fin.
            feed_bidi_error(*call->state,
                            Status{StatusCode::Cancelled,
                                   "transport: stream closed"});
            if (channel) {
                Status final_status;
                {
                    std::lock_guard<std::mutex> lock(call->state->mtx);
                    if (call->state->final_valid) {
                        final_status = call->state->final_status;
                    }
                }
                safe_sink_invoke(channel->metric_sink_, [&](auto& s) {
                    s.on_stream_closed("msquic", call->method, final_status);
                });
            }
            channel->untrack_bidi_call(stream);
            return QUIC_STATUS_SUCCESS;
        }

        default:
            return QUIC_STATUS_SUCCESS;
    }
}

QUIC_STATUS QUIC_API msquic_client_conn_callback(HQUIC /*conn*/, void* ctx,
                                                 QUIC_CONNECTION_EVENT* ev) {
    auto* channel = static_cast<MsquicChannel*>(ctx);
    switch (ev->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED: {
            {
                std::lock_guard<std::mutex> lock(channel->mtx_);
                channel->conn_state_ = MsquicChannel::ConnState::Connected;
            }
            channel->conn_cv_.notify_all();
            safe_sink_invoke(channel->metric_sink_, [](auto& s) {
                s.on_connection_opened("msquic");
            });
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT: {
            {
                std::lock_guard<std::mutex> lock(channel->mtx_);
                if (channel->conn_state_ != MsquicChannel::ConnState::Connected) {
                    channel->conn_state_ = MsquicChannel::ConnState::Failed;
                    channel->conn_error_ = Status{
                        quic_status_to_status_code(
                            ev->SHUTDOWN_INITIATED_BY_TRANSPORT.Status),
                        "transport: connection failed " +
                            quic_status_hex(
                                ev->SHUTDOWN_INITIATED_BY_TRANSPORT.Status)};
                }
            }
            channel->conn_cv_.notify_all();
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER: {
            {
                std::lock_guard<std::mutex> lock(channel->mtx_);
                if (channel->conn_state_ != MsquicChannel::ConnState::Connected) {
                    channel->conn_state_ = MsquicChannel::ConnState::Failed;
                    channel->conn_error_ = Status{
                        StatusCode::Unavailable,
                        "transport: connection refused by peer"};
                }
            }
            channel->conn_cv_.notify_all();
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
            Status final_status;
            {
                std::lock_guard<std::mutex> lock(channel->mtx_);
                if (channel->conn_state_ != MsquicChannel::ConnState::Connected) {
                    channel->conn_state_ = MsquicChannel::ConnState::Failed;
                    if (channel->conn_error_.ok()) {
                        channel->conn_error_ = Status{
                            StatusCode::Unavailable,
                            "transport: connection closed before ready"};
                    }
                }
                final_status = channel->conn_error_;
            }
            channel->conn_cv_.notify_all();
            safe_sink_invoke(channel->metric_sink_, [&](auto& s) {
                s.on_connection_closed("msquic", final_status);
            });
            // The handle is freed by MsquicChannel::close(); msquic permits
            // holding the handle past SHUTDOWN_COMPLETE.
            return QUIC_STATUS_SUCCESS;
        }

        default:
            return QUIC_STATUS_SUCCESS;
    }
}

// MsquicBidiStream itself lives in msquic_bidi_stream.{hpp,cpp} — one
// shared implementation serves both the client (here) and the server
// (msquic_listener.cpp::run_bidi_handler).

// ── MsquicChannel ────────────────────────────────────────────────────────────

MsquicChannel::MsquicChannel(Endpoint target, Credentials creds,
                             BackoffPolicy backoff,
                             std::shared_ptr<TransportMetricSink> metric_sink)
    : target_(std::move(target)),
      creds_(std::move(creds)),
      backoff_(backoff),
      metric_sink_(std::move(metric_sink)) {}

MsquicChannel::~MsquicChannel() {
    close();
    yuzu::secure_zero(creds_.client_key_pem);
    yuzu::secure_zero(creds_.server_key_pem);
}

Status MsquicChannel::connect_and_wait(std::chrono::milliseconds deadline) {
    std::unique_lock<std::mutex> lock(mtx_);
    if (conn_state_ == ConnState::Connected) return Status{};
    if (conn_state_ == ConnState::Failed) return conn_error_;
    if (closed_.load(std::memory_order_acquire)) {
        return Status{StatusCode::Unavailable, "transport: channel closed"};
    }

    if (conn_state_ == ConnState::Idle) {
        // YUZU_ALLOW_INSECURE_TLS posture gate (#376 PR 3 increment 5).
        if (Status posture =
                check_insecure_tls_posture(creds_, /*client=*/true);
            !posture.ok()) {
            conn_state_ = ConnState::Failed;
            conn_error_ = posture;
            return conn_error_;
        }

        auto& handle = MsQuicApi::instance();
        if (!handle.ok()) {
            conn_state_ = ConnState::Failed;
            conn_error_ = Status{StatusCode::Internal,
                                 "transport: " + handle.init_error()};
            return conn_error_;
        }
        const auto* api = handle.api();

        // Multi-ALPN (#376 PR 3 increment 5): all configured protocols
        // are offered. Empty list is promoted to {"yuzu/1"}.
        auto       alpn       = build_alpn_buffers(creds_.alpn_protocols);
        const auto alpn_count = static_cast<uint32_t>(alpn.buffers.size());

        QUIC_SETTINGS settings{};
        settings.IdleTimeoutMs       = 5000;
        settings.IsSet.IdleTimeoutMs = TRUE;

        QUIC_STATUS st = api->ConfigurationOpen(handle.registration(),
                                                alpn.buffers.data(), alpn_count,
                                                &settings, sizeof(settings),
                                                nullptr, &configuration_);
        if (QUIC_FAILED(st)) {
            configuration_ = nullptr;
            conn_state_    = ConnState::Failed;
            conn_error_    = Status{StatusCode::Internal,
                                 "transport: ConfigurationOpen failed " +
                                     quic_status_hex(st)};
            return conn_error_;
        }

        // INCREMENT-2 SCOPE: client carries no client certificate, and
        // honours verify_peer=false by disabling server-cert validation.
        // Real mTLS + CA-pinned server-cert validation is increment 5.
        QUIC_CREDENTIAL_CONFIG cred{};
        cred.Type  = QUIC_CREDENTIAL_TYPE_NONE;
        cred.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
        if (!creds_.verify_peer) {
            cred.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        }
        st = api->ConfigurationLoadCredential(configuration_, &cred);
        if (QUIC_FAILED(st)) {
            api->ConfigurationClose(configuration_);
            configuration_ = nullptr;
            conn_state_    = ConnState::Failed;
            conn_error_    = Status{StatusCode::Unauthenticated,
                                 "transport: ConfigurationLoadCredential "
                                    "failed " +
                                     quic_status_hex(st)};
            return conn_error_;
        }

        st = api->ConnectionOpen(handle.registration(),
                                 msquic_client_conn_callback, this,
                                 &connection_);
        if (QUIC_FAILED(st)) {
            connection_ = nullptr;
            api->ConfigurationClose(configuration_);
            configuration_ = nullptr;
            conn_state_    = ConnState::Failed;
            conn_error_    = Status{StatusCode::Internal,
                                 "transport: ConnectionOpen failed " +
                                     quic_status_hex(st)};
            return conn_error_;
        }

        st = api->ConnectionStart(connection_, configuration_,
                                  QUIC_ADDRESS_FAMILY_UNSPEC,
                                  target_.host.c_str(), target_.port);
        if (QUIC_FAILED(st)) {
            conn_state_ = ConnState::Failed;
            conn_error_ = Status{StatusCode::Unavailable,
                                 "transport: ConnectionStart failed " +
                                     quic_status_hex(st)};
            return conn_error_;
        }
        conn_state_ = ConnState::Connecting;
    }

    auto pred = [this] {
        return conn_state_ == ConnState::Connected ||
               conn_state_ == ConnState::Failed;
    };
    if (deadline <= std::chrono::milliseconds::zero()) {
        conn_cv_.wait(lock, pred);
    } else if (!conn_cv_.wait_for(lock, deadline, pred)) {
        return Status{StatusCode::DeadlineExceeded,
                      "transport: connection establishment timed out"};
    }
    return conn_state_ == ConnState::Connected ? Status{} : conn_error_;
}

void MsquicChannel::untrack_call(HQUIC stream) {
    std::shared_ptr<ClientUnaryCall> released;  // freed outside the lock
    {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = live_calls_.find(stream);
        if (it != live_calls_.end()) {
            released = std::move(it->second);
            live_calls_.erase(it);
        }
    }
}

void MsquicChannel::untrack_bidi_call(HQUIC stream) {
    std::shared_ptr<ClientBidiCall> released;  // freed outside the lock
    {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = live_bidi_calls_.find(stream);
        if (it != live_bidi_calls_.end()) {
            released = std::move(it->second);
            live_bidi_calls_.erase(it);
        }
    }
}

CallResult MsquicChannel::unary(std::string_view method,
                                const CallContext& ctx,
                                const SerializableMessage& request,
                                SerializableMessage& response) {
    if (closed_.load(std::memory_order_acquire)) {
        return CallResult{
            Status{StatusCode::Unavailable, "transport: channel closed"}, {}};
    }

    Status conn = connect_and_wait(std::chrono::milliseconds::zero());
    if (!conn.ok()) return CallResult{conn, {}};

    const auto* api = MsQuicApi::instance().api();

    // Serialise the request before opening the stream so a serialisation
    // failure does not leave a half-open stream behind.
    std::string request_body;
    if (!request.serialize(request_body)) {
        return CallResult{Status{StatusCode::Internal,
                                 "transport: request serialisation failed"},
                          {}};
    }
    std::string request_frame;
    if (!encode_frame(request_body, 0, request_frame)) {
        return CallResult{
            Status{StatusCode::ResourceExhausted,
                   "transport: request frame exceeds the frame-size cap"},
            {}};
    }

    // Negative-deadline clamp (#915 / UP-110 / arch-S1) and absolute-
    // deadline encoding (#376 PR 3 increment 4). zero ctx.deadline means
    // "no deadline" — encode as deadline_unix_millis=0; positive values
    // become an absolute system-clock millisecond deadline that the
    // server can compare against its own clock to detect already-expired
    // calls before the handler runs.
    auto effective_deadline = ctx.deadline;
    if (effective_deadline < std::chrono::milliseconds::zero()) {
        effective_deadline = std::chrono::milliseconds::zero();
    }
    std::uint64_t deadline_unix_millis = 0;
    if (effective_deadline > std::chrono::milliseconds::zero()) {
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
        deadline_unix_millis =
            static_cast<std::uint64_t>(now_ms + effective_deadline.count());
    }

    pb::HandshakeHello hello;
    hello.set_method(std::string(method));
    for (const auto& [k, v] : ctx.metadata) {
        (*hello.mutable_metadata())[k] = v;
    }
    hello.set_deadline_unix_millis(deadline_unix_millis);
    std::string hello_body;
    if (!hello.SerializeToString(&hello_body)) {
        return CallResult{Status{StatusCode::Internal,
                                 "transport: HandshakeHello serialisation "
                                 "failed"},
                          {}};
    }
    std::string hello_frame;
    if (!encode_frame(hello_body, 0, hello_frame)) {
        return CallResult{Status{StatusCode::ResourceExhausted,
                                 "transport: HandshakeHello frame exceeds "
                                 "the frame-size cap"},
                          {}};
    }

    auto call = std::make_shared<ClientUnaryCall>(kDefaultMaxFrameSize);
    call->channel = this;
    call->self    = call;

    HQUIC stream = nullptr;
    QUIC_STATUS st = api->StreamOpen(connection_, QUIC_STREAM_OPEN_FLAG_NONE,
                                     msquic_client_stream_callback, call.get(),
                                     &stream);
    if (QUIC_FAILED(st)) {
        return CallResult{Status{StatusCode::Unavailable,
                                 "transport: StreamOpen failed " +
                                     quic_status_hex(st)},
                          {}};
    }
    call->stream = stream;
    safe_sink_invoke(metric_sink_, [&](auto& s) {
        s.on_stream_opened("msquic", method);
    });
    {
        std::lock_guard<std::mutex> lock(mtx_);
        live_calls_[stream] = call;
    }

    st = api->StreamStart(stream, QUIC_STREAM_START_FLAG_NONE);
    if (QUIC_FAILED(st)) {
        untrack_call(stream);
        api->StreamClose(stream);
        return CallResult{Status{StatusCode::Unavailable,
                                 "transport: StreamStart failed " +
                                     quic_status_hex(st)},
                          {}};
    }

    // HandshakeHello, then the request frame with FIN (client half-close —
    // a unary client sends exactly two frames then stops writing).
    if (!send_framed(stream, std::move(hello_frame), /*fin=*/false,
                     metric_sink_) ||
        !send_framed(stream, std::move(request_frame), /*fin=*/true,
                     metric_sink_)) {
        finish_call(call.get(),
                    Status{StatusCode::Unavailable,
                           "transport: failed to send request frames"});
    }

    // Block until the stream completes (peer FIN, abort, or shutdown).
    // The wait is bounded by the caller's CallContext::deadline if
    // positive (#376 PR 3 increment 4); otherwise a 10 s safety net
    // protects against a wedged handler or a lost QUIC event hanging
    // the caller indefinitely (governance UP-5 / qe-BLOCKING).
    const auto wait_cap =
        effective_deadline > std::chrono::milliseconds::zero()
            ? effective_deadline
            : std::chrono::milliseconds(10000);
    bool completed = false;
    {
        std::unique_lock<std::mutex> lock(call->mtx);
        completed = call->cv.wait_for(lock, wait_cap,
                                      [&call] { return call->done; });
        if (!completed) {
            call->done            = true;  // a late finish_call no-ops
            call->transport_error = Status{
                StatusCode::DeadlineExceeded,
                effective_deadline > std::chrono::milliseconds::zero()
                    ? "transport: unary deadline expired"
                    : "transport: unary call did not complete within 10s"};
        }
    }
    if (!completed) {
        // Abort the stream so SHUTDOWN_COMPLETE fires and untracks it.
        // This may race a real SHUTDOWN_COMPLETE callback already running
        // untrack_call + StreamClose — that is benign: `call` stays alive
        // via the live_calls_ shared_ptr, and StreamShutdown on a handle
        // being closed is a msquic-tolerated no-op (governance Gate-7).
        api->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }

    // Collect the call outcome.
    std::vector<std::string> frames;
    Status transport_error;
    bool   peer_clean_fin = false;
    {
        std::lock_guard<std::mutex> lock(call->mtx);
        frames          = std::move(call->frames);
        transport_error = call->transport_error;
        peer_clean_fin  = call->peer_clean_fin;
    }
    if (!transport_error.ok()) {
        safe_sink_invoke(metric_sink_, [&](auto& s) {
            s.on_stream_closed("msquic", method, transport_error);
        });
        return CallResult{transport_error, {}};
    }
    // The frame-count interpretation below is only sound when the peer
    // half-closed cleanly. A stream ended by abort / connection drop /
    // mid-response crash has an indeterminate frame sequence — a lone
    // frame could be a truncated response, NOT a trailer, and parsing a
    // response as a TrailingStatus would fabricate an RPC status
    // (governance UP-14 / CH-3).
    if (!peer_clean_fin) {
        Status st{StatusCode::Unavailable,
                  "transport: stream ended without a clean peer half-close"};
        safe_sink_invoke(metric_sink_, [&](auto& s) {
            s.on_stream_closed("msquic", method, st);
        });
        return CallResult{st, {}};
    }

    // Interpret the collected frames. Wire contract for unary
    // (peer_clean_fin == true):
    //   success -> [response frame][TrailingStatus frame]
    //   failure -> [TrailingStatus frame]
    auto parse_trailer = [](const std::string& body) -> Status {
        pb::TrailingStatus trailer;
        if (!trailer.ParseFromString(body)) {
            return Status{StatusCode::DataLoss,
                          "transport: malformed TrailingStatus frame"};
        }
        return Status{static_cast<StatusCode>(static_cast<int>(trailer.code())),
                      sanitise_status_detail(trailer.detail())};
    };

    auto emit_close = [this, method](const Status& st) {
        safe_sink_invoke(metric_sink_, [&](auto& s) {
            s.on_stream_closed("msquic", method, st);
        });
    };

    if (frames.empty()) {
        Status st{StatusCode::Unknown,
                  "transport: peer closed without trailing status"};
        emit_close(st);
        return CallResult{st, {}};
    }
    if (frames.size() == 1) {
        // Failure path — only the trailer was sent.
        Status t = parse_trailer(frames[0]);
        emit_close(t);
        return CallResult{t, {}};
    }
    // Success path — frames[0] is the response, frames[1] the trailer.
    if (!response.parse(frames[0])) {
        Status st{StatusCode::DataLoss,
                  "transport: response frame failed to parse"};
        emit_close(st);
        return CallResult{st, {}};
    }
    if (frames.size() > 2) {
        Status st{StatusCode::DataLoss,
                  "transport: unexpected frame after TrailingStatus"};
        emit_close(st);
        return CallResult{st, {}};
    }
    Status t = parse_trailer(frames[1]);
    emit_close(t);
    return CallResult{t, {}};
}

std::unique_ptr<BidiStream> MsquicChannel::bidi_stream(std::string_view method,
                                                       const CallContext& ctx) {
    auto state  = std::make_shared<BidiStreamState>();
    state->self = state;

    // Helper: pre-populate the state with a terminal status so the
    // returned MsquicBidiStream's read/write/final_status all see the
    // failure immediately. Used for connect / serialize / StreamOpen
    // failures BEFORE the stream is live.
    auto fail_with = [&state](Status s) -> std::unique_ptr<BidiStream> {
        {
            std::lock_guard<std::mutex> lock(state->mtx);
            state->final_status  = std::move(s);
            state->final_valid   = true;
            state->stream_closed = true;
            state->peer_fin      = true;
        }
        return std::make_unique<MsquicBidiStream>(std::move(state),
                                                  /*server_side=*/false);
    };

    if (closed_.load(std::memory_order_acquire)) {
        return fail_with(
            Status{StatusCode::Unavailable, "transport: channel closed"});
    }
    Status conn = connect_and_wait(std::chrono::milliseconds::zero());
    if (!conn.ok()) return fail_with(conn);

    const auto* api = MsQuicApi::instance().api();

    // Encode the HandshakeHello. For unary the FIN rides the request
    // frame; for bidi the client keeps writing, so the hello is sent
    // without FIN. CallContext::deadline becomes an absolute system-
    // clock millisecond deadline on the wire (#376 PR 3 increment 4);
    // negative is clamped to zero (#915 / UP-110 / arch-S1).
    auto bidi_deadline = ctx.deadline;
    if (bidi_deadline < std::chrono::milliseconds::zero()) {
        bidi_deadline = std::chrono::milliseconds::zero();
    }
    std::uint64_t bidi_deadline_unix_millis = 0;
    if (bidi_deadline > std::chrono::milliseconds::zero()) {
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
        bidi_deadline_unix_millis =
            static_cast<std::uint64_t>(now_ms + bidi_deadline.count());
    }
    pb::HandshakeHello hello;
    hello.set_method(std::string(method));
    for (const auto& [k, v] : ctx.metadata) {
        (*hello.mutable_metadata())[k] = v;
    }
    hello.set_deadline_unix_millis(bidi_deadline_unix_millis);
    std::string hello_body;
    if (!hello.SerializeToString(&hello_body)) {
        return fail_with(Status{
            StatusCode::Internal,
            "transport: HandshakeHello serialisation failed"});
    }
    std::string hello_frame;
    if (!encode_frame(hello_body, 0, hello_frame)) {
        return fail_with(Status{
            StatusCode::ResourceExhausted,
            "transport: HandshakeHello frame exceeds the frame-size cap"});
    }

    auto call     = std::make_shared<ClientBidiCall>(kDefaultMaxFrameSize);
    call->channel = this;
    call->self    = call;
    call->state   = state;
    call->method  = std::string(method);

    HQUIC stream = nullptr;
    QUIC_STATUS st =
        api->StreamOpen(connection_, QUIC_STREAM_OPEN_FLAG_NONE,
                        msquic_client_bidi_stream_callback, call.get(),
                        &stream);
    if (QUIC_FAILED(st)) {
        return fail_with(Status{StatusCode::Unavailable,
                                "transport: StreamOpen failed " +
                                    quic_status_hex(st)});
    }
    call->stream  = stream;
    state->stream = stream;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        live_bidi_calls_[stream] = call;
    }
    safe_sink_invoke(metric_sink_, [&](auto& s) {
        s.on_stream_opened("msquic", call->method);
    });

    st = api->StreamStart(stream, QUIC_STREAM_START_FLAG_NONE);
    if (QUIC_FAILED(st)) {
        untrack_bidi_call(stream);
        api->StreamClose(stream);
        // HP-2: stream_opened already fired above; emit the matching
        // stream_closed so opened/closed counters stay balanced when the
        // start half of the handshake fails.
        Status fail_st{StatusCode::Unavailable,
                       "transport: StreamStart failed " + quic_status_hex(st)};
        safe_sink_invoke(metric_sink_, [&](auto& s) {
            s.on_stream_closed("msquic", call->method, fail_st);
        });
        return fail_with(fail_st);
    }

    // Send the HandshakeHello (no FIN — bidi continues writing).
    if (!send_framed(stream, std::move(hello_frame), /*fin=*/false,
                     metric_sink_)) {
        api->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        feed_bidi_error(*state,
                        Status{StatusCode::Unavailable,
                               "transport: failed to send HandshakeHello"});
        // Stream will SHUTDOWN_COMPLETE -> untrack. The MsquicBidiStream
        // wrapping `state` reflects the failure via final_status().
    }

    return std::make_unique<MsquicBidiStream>(std::move(state),
                                              /*server_side=*/false);
}

bool MsquicChannel::wait_for_connected(std::chrono::milliseconds deadline) {
    return connect_and_wait(deadline).ok();
}

void MsquicChannel::close() {
    if (closed_.exchange(true, std::memory_order_acq_rel)) {
        return;  // idempotent
    }

    // Snapshot and clear the msquic handles under the lock, then close
    // them OUTSIDE the lock: ConnectionClose blocks until every callback
    // for the connection has returned, and those callbacks (stream
    // SHUTDOWN_COMPLETE -> untrack_call) take mtx_.
    HQUIC connection = nullptr;
    HQUIC configuration = nullptr;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        connection     = connection_;
        configuration  = configuration_;
        connection_    = nullptr;
        configuration_ = nullptr;
    }

    const auto* api = MsQuicApi::instance().api();
    if (api != nullptr && connection != nullptr) {
        api->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                0);
        api->ConnectionClose(connection);  // blocks until callbacks drain
    }
    if (api != nullptr && configuration != nullptr) {
        api->ConfigurationClose(configuration);
    }

    // RELIES ON: ConnectionClose blocks until every stream callback for
    // the connection has returned, so each stream's SHUTDOWN_COMPLETE
    // (and its untrack_call / untrack_bidi_call) has already run by
    // here — live_calls_ and live_bidi_calls_ are normally empty. The
    // clear()s are a defensive catch, not the primary drain (gov hp-2).
    std::lock_guard<std::mutex> lock(mtx_);
    live_calls_.clear();
    live_bidi_calls_.clear();
}

}  // namespace yuzu::transport::msquic_backend
