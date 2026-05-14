// SPDX-License-Identifier: Apache-2.0
// #376 PR 3, increment 2 — MsquicChannel: client connection establishment
// and synchronous unary RPC over a QUIC stream.
//
// Out of scope for increment 2: the bidi path (increment 3 — bidi_stream()
// still returns the skeleton stub), per-call deadlines (increment 4),
// mTLS / server-cert verification (increment 5 — increment 2 honours
// verify_peer=false only), the metric sink (increment 6).

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

#include "msquic_framing.hpp"
#include "msquic_internal_helpers.hpp"
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

    explicit ClientUnaryCall(std::size_t max_frame) : decoder(max_frame) {}
};

namespace {

constexpr const char* kBidiNotImplemented =
    "transport: msquic bidi streams not yet implemented (#376 PR 3 "
    "increment 3)";

// Owned outbound buffer; the SendBuf* is the StreamSend client context,
// freed on SEND_COMPLETE.
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
// is freed in the stream's SEND_COMPLETE handler.
bool send_framed(HQUIC stream, std::string framed, bool fin) {
    const auto* api = MsQuicApi::instance().api();
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
    return true;
}

// Mark a call complete and wake unary().
void finish_call(ClientUnaryCall* call, Status error) {
    {
        std::lock_guard<std::mutex> lock(call->mtx);
        if (call->done) return;
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
            {
                std::lock_guard<std::mutex> lock(call->mtx);
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
                finish_call(call, Status{});
            }
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            finish_call(call, Status{});
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
            }
            channel->conn_cv_.notify_all();
            // The handle is freed by MsquicChannel::close(); msquic permits
            // holding the handle past SHUTDOWN_COMPLETE.
            return QUIC_STATUS_SUCCESS;
        }

        default:
            return QUIC_STATUS_SUCCESS;
    }
}

// ── MsquicBidiStream skeleton (real impl: increment 3) ───────────────────────

bool MsquicBidiStream::write(const SerializableMessage&,
                             std::chrono::milliseconds) {
    return false;
}
bool MsquicBidiStream::read(SerializableMessage&, std::chrono::milliseconds) {
    return false;
}
void MsquicBidiStream::writes_done() {}
Status MsquicBidiStream::final_status() {
    return Status{StatusCode::Unimplemented, kBidiNotImplemented};
}
const std::map<std::string, std::string>&
MsquicBidiStream::trailing_metadata() const {
    return trailing_metadata_;
}
void MsquicBidiStream::cancel() {}

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
        auto& handle = MsQuicApi::instance();
        if (!handle.ok()) {
            conn_state_ = ConnState::Failed;
            conn_error_ = Status{StatusCode::Internal,
                                 "transport: " + handle.init_error()};
            return conn_error_;
        }
        const auto* api = handle.api();

        std::string alpn_str = creds_.alpn_protocols.empty()
                                   ? "yuzu/1"
                                   : creds_.alpn_protocols.front();
        QUIC_BUFFER alpn{};
        alpn.Length = static_cast<uint32_t>(alpn_str.size());
        alpn.Buffer = reinterpret_cast<uint8_t*>(alpn_str.data());

        QUIC_SETTINGS settings{};
        settings.IdleTimeoutMs       = 30000;
        settings.IsSet.IdleTimeoutMs = TRUE;

        QUIC_STATUS st = api->ConfigurationOpen(handle.registration(), &alpn, 1,
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

    pb::HandshakeHello hello;
    hello.set_method(std::string(method));
    for (const auto& [k, v] : ctx.metadata) {
        (*hello.mutable_metadata())[k] = v;
    }
    // Deadline plumbing is increment 4; increment 2 sends "no deadline".
    hello.set_deadline_unix_millis(0);
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
    if (!send_framed(stream, std::move(hello_frame), /*fin=*/false) ||
        !send_framed(stream, std::move(request_frame), /*fin=*/true)) {
        finish_call(call.get(),
                    Status{StatusCode::Unavailable,
                           "transport: failed to send request frames"});
    }

    // Block until the stream completes (peer FIN, abort, or shutdown).
    {
        std::unique_lock<std::mutex> lock(call->mtx);
        call->cv.wait(lock, [&call] { return call->done; });
    }

    // Interpret the collected frames. Wire contract for unary:
    //   success -> [response frame][TrailingStatus frame]
    //   failure -> [TrailingStatus frame]
    std::vector<std::string> frames;
    Status transport_error;
    {
        std::lock_guard<std::mutex> lock(call->mtx);
        frames          = std::move(call->frames);
        transport_error = call->transport_error;
    }
    if (!transport_error.ok()) {
        return CallResult{transport_error, {}};
    }

    auto parse_trailer = [](const std::string& body) -> Status {
        pb::TrailingStatus trailer;
        if (!trailer.ParseFromString(body)) {
            return Status{StatusCode::DataLoss,
                          "transport: malformed TrailingStatus frame"};
        }
        return Status{static_cast<StatusCode>(static_cast<int>(trailer.code())),
                      sanitise_status_detail(trailer.detail())};
    };

    if (frames.empty()) {
        return CallResult{Status{StatusCode::Unknown,
                                 "transport: peer closed without trailing "
                                 "status"},
                          {}};
    }
    if (frames.size() == 1) {
        // Failure path — only the trailer was sent.
        return CallResult{parse_trailer(frames[0]), {}};
    }
    // Success path — frames[0] is the response, frames[1] the trailer.
    if (!response.parse(frames[0])) {
        return CallResult{Status{StatusCode::DataLoss,
                                 "transport: response frame failed to parse"},
                          {}};
    }
    if (frames.size() > 2) {
        return CallResult{Status{StatusCode::DataLoss,
                                 "transport: unexpected frame after "
                                 "TrailingStatus"},
                          {}};
    }
    return CallResult{parse_trailer(frames[1]), {}};
}

std::unique_ptr<BidiStream> MsquicChannel::bidi_stream(std::string_view,
                                                       const CallContext&) {
    // Real bidi streams land in #376 PR 3 increment 3.
    return std::make_unique<MsquicBidiStream>();
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

    // Any calls still tracked had their streams closed by ConnectionClose.
    std::lock_guard<std::mutex> lock(mtx_);
    live_calls_.clear();
}

}  // namespace yuzu::transport::msquic_backend
