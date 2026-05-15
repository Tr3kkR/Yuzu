// SPDX-License-Identifier: Apache-2.0
// #376 PR 3, increment 2 — MsquicServerListener: real listener bring-up,
// the three msquic callback levels, HandshakeHello dispatch, and unary
// handler invocation on a worker pool.
//
// Out of scope for increment 2 (later increments): the bidi path
// (increment 3), per-frame deadlines (increment 4), mTLS / client-cert
// verification / in-memory PEM (increment 5 — increment 2 loads the
// server cert via a temp file, the spike's known-good path), the metric
// sink (increment 6), and the bounded-dispatcher saturation contract
// (increment 7).

#include "msquic_listener.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <typeinfo>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <unistd.h>  // close, unlink
#endif

#include <spdlog/spdlog.h>

#include "msquic_bidi_stream.hpp"
#include "msquic_framing.hpp"
#include "msquic_internal_helpers.hpp"
#include "msquic_stream_state.hpp"
#include "transport.pb.h"  // HandshakeHello, TrailingStatus

namespace yuzu::transport::msquic_backend {

namespace pb = ::yuzu::transport::framing::v1;

// ── Per-stream server-side call state ────────────────────────────────────────

struct ServerStreamCall {
    MsquicServerListener* listener = nullptr;
    HQUIC                 stream   = nullptr;

    // weak self-reference: callbacks recover the raw pointer from the
    // msquic stream context for the fast path, and lock() this to obtain
    // an owning shared_ptr when handing work to the worker pool.
    std::weak_ptr<ServerStreamCall> self;

    FrameDecoder decoder;

    // `phase` is owned exclusively by the msquic stream callback, which
    // msquic delivers serially per stream — there is no concurrent
    // writer (governance cpp-S2 / UP-7: the worker thread does not
    // touch it). For Bidi the worker reads/writes only `bidi_state`
    // (the shared BidiStreamState), not `phase`; the callback continues
    // routing inbound frames into bidi_state until SHUTDOWN_COMPLETE.
    enum class Phase { AwaitingHello, AwaitingRequest, Dispatched, Bidi, Done };
    Phase phase = Phase::AwaitingHello;

    CallContext ctx;  // populated from HandshakeHello before dispatch

    // Resolved unary registration (copied out of the listener's handler
    // map once the HandshakeHello method is known).
    bool                                                  is_unary = false;
    std::function<std::unique_ptr<SerializableMessage>()>  request_factory;
    std::function<std::unique_ptr<SerializableMessage>()>  response_factory;
    UnaryHandler                                          unary_handler;

    // Resolved bidi registration. `bidi_state` is the shared blocking-
    // bridge state passed to the handler via MsquicBidiStream; the
    // RECEIVE callback feeds decoded frames into it. Set up by
    // dispatch_stream_call's bidi branch.
    BidiStreamHandler                bidi_handler;
    std::shared_ptr<BidiStreamState> bidi_state;

    // Serialises a worker thread's outbound StreamSend / StreamShutdown
    // against the SHUTDOWN_COMPLETE callback's StreamClose (governance
    // UP-1 / CH-1): a peer that aborts mid-handler can drive
    // SHUTDOWN_COMPLETE while the worker still holds `this` and would
    // otherwise call StreamSend on the freed HQUIC. Held only briefly
    // around the msquic stream op.
    std::mutex mtx;
    bool       stream_closed = false;

    explicit ServerStreamCall(std::size_t max_frame) : decoder(max_frame) {}
};

namespace {

// Owned outbound buffer. The QUIC_BUFFER points into `bytes`; the
// SendBuf* is the StreamSend client context, freed on SEND_COMPLETE.
// Raw new/delete: ownership is transferred across the msquic C ABI —
// the StreamSend client context is a void* msquic hands back at
// SEND_COMPLETE, which no RAII type spans.
struct SendBuf {
    QUIC_BUFFER quic{};
    std::string bytes;
    explicit SendBuf(std::string b) : bytes(std::move(b)) {
        quic.Buffer = reinterpret_cast<uint8_t*>(bytes.data());
        quic.Length = static_cast<uint32_t>(bytes.size());
    }
};

// Write PEM bytes to a 0600 temp file so msquic's QUIC_CERTIFICATE_FILE
// path can load them. INCREMENT-5 NOTE: this whole temp-file dance goes
// away when increment 5 lands in-memory PEM->PKCS12 conversion; the
// Credentials contract wants private-key bytes never written to disk.
std::optional<std::string> write_temp_pem(const std::string& pem,
                                          std::string& err) {
#ifdef _WIN32
    (void)pem;
    err = "transport: msquic credential temp-file path is POSIX-only in "
          "increment 2; in-memory PKCS12 lands in #376 PR 3 increment 5";
    return std::nullopt;
#else
    char path[] = "/tmp/yuzu-msquic-pem-XXXXXX";
    int fd = ::mkstemp(path);  // creates 0600
    if (fd < 0) {
        err = "transport: mkstemp failed for credential temp file";
        return std::nullopt;
    }
    std::size_t off = 0;
    while (off < pem.size()) {
        ssize_t n = ::write(fd, pem.data() + off, pem.size() - off);
        if (n <= 0) {
            ::close(fd);
            ::unlink(path);
            err = "transport: write failed for credential temp file";
            return std::nullopt;
        }
        off += static_cast<std::size_t>(n);
    }
    ::close(fd);
    return std::string(path);
#endif
}

QUIC_STATUS map_decoder_error_to_quic(StatusCode) noexcept {
    // The decoder only ever yields ResourceExhausted; the stream is
    // aborted regardless of which non-Ok code it is.
    return QUIC_STATUS_ABORTED;
}

}  // namespace

// ── Outbound helpers (free, used by the worker-pool task) ────────────────────

namespace {

// Send one framed payload on the stream. `fin` half-closes the send
// direction after this buffer. Returns false if the stream is already
// closed or StreamSend failed. Takes call->mtx so a worker thread's
// StreamSend cannot race the SHUTDOWN_COMPLETE callback's StreamClose
// (governance UP-1 / CH-1).
//
// PRECONDITION: msquic does not synchronously re-enter the stream
// callback from StreamSend/StreamShutdown/StreamClose (its documented
// model — callbacks come from msquic worker threads, not inline). The
// non-recursive call->mtx held here and in the SHUTDOWN_COMPLETE handler
// relies on that.
bool send_frame(ServerStreamCall* call, std::string payload, bool fin) {
    std::lock_guard<std::mutex> lock(call->mtx);
    if (call->stream_closed) return false;
    const auto* api = MsQuicApi::instance().api();
    auto* sb = new SendBuf(std::move(payload));
    const QUIC_SEND_FLAGS flags =
        fin ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE;
    QUIC_STATUS st = api->StreamSend(call->stream, &sb->quic, 1, flags, sb);
    if (QUIC_FAILED(st)) {
        spdlog::warn("yuzu::transport[msquic]: StreamSend failed {}",
                     quic_status_hex(st));
        delete sb;
        return false;
    }
    return true;
}

// Abort the stream. Takes call->mtx and no-ops if the stream is already
// closed — same race guard as send_frame (governance UP-1 / CH-1).
void abort_stream(ServerStreamCall* call) {
    std::lock_guard<std::mutex> lock(call->mtx);
    if (call->stream_closed) return;
    MsQuicApi::instance().api()->StreamShutdown(
        call->stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
}

// Encode a TrailingStatus message and send it as the final frame.
void send_trailing_status(ServerStreamCall* call, const Status& status) {
    pb::TrailingStatus trailer;
    trailer.set_code(static_cast<pb::StatusCode>(static_cast<int>(status.code)));
    trailer.set_detail(sanitise_status_detail(status.detail));
    std::string body;
    if (!trailer.SerializeToString(&body)) {
        // Should not happen for a trivial message; abort the stream.
        abort_stream(call);
        return;
    }
    std::string framed;
    // TrailingStatus is transport-internal and small; the default cap
    // always accommodates it.
    if (!encode_frame(body, 0, framed)) {
        abort_stream(call);
        return;
    }
    send_frame(call, std::move(framed), /*fin=*/true);
}

// Run a resolved unary handler and stream back the response + trailer.
// Executes on a worker-pool thread; `keep` keeps the call alive for the
// duration even if the stream is torn down concurrently.
void run_unary_handler(std::shared_ptr<ServerStreamCall> keep,
                       std::string request_bytes) {
    ServerStreamCall* call = keep.get();

    auto request  = call->request_factory();
    auto response = call->response_factory();

    Status status;
    if (!request->parse(request_bytes)) {
        status = Status{StatusCode::DataLoss,
                        "transport: unary request frame failed to parse"};
    } else {
        try {
            status = call->unary_handler(call->ctx, *request, *response);
        } catch (const std::exception& e) {
            spdlog::error(
                "yuzu::transport[msquic]: unary handler raised std::exception "
                "— type={} what={}",
                typeid(e).name(), e.what());
            status = Status{StatusCode::Internal,
                            "transport: handler raised exception"};
        } catch (...) {
            spdlog::error(
                "yuzu::transport[msquic]: unary handler raised non-std "
                "exception");
            status = Status{StatusCode::Internal,
                            "transport: handler raised non-std exception"};
        }
    }

    // On success the response message precedes the trailer; on failure
    // only the trailer is sent (gRPC unary semantics).
    if (status.ok()) {
        std::string response_body;
        if (!response->serialize(response_body)) {
            status = Status{StatusCode::Internal,
                            "transport: response serialisation failed"};
        } else {
            std::string framed;
            if (!encode_frame(response_body, 0, framed)) {
                status = Status{StatusCode::ResourceExhausted,
                                "transport: response frame exceeds cap"};
            } else {
                send_frame(call, std::move(framed), /*fin=*/false);
            }
        }
    }
    send_trailing_status(call, status);
    // NOTE: `phase` is deliberately NOT written here. The msquic stream
    // callback already set it to Dispatched before submitting this task
    // (governance hp-1 / cpp-S2 / UP-7: a write here would be a second
    // writer racing the serial callback thread).
}

// Run a resolved bidi handler. Executes on a worker-pool thread; `keep`
// keeps the ServerStreamCall alive even if the stream is torn down
// concurrently. The MsquicBidiStream is scoped to keep the trailer
// emission BEFORE the dtor (which would otherwise ABORT a stream whose
// wire FIN has not yet been sent).
void run_bidi_handler(std::shared_ptr<ServerStreamCall> keep,
                      std::shared_ptr<BidiStreamState>  bidi_state,
                      BidiStreamHandler                 handler,
                      CallContext                       ctx) {
    Status status;
    {
        MsquicBidiStream bidi_stream(bidi_state, /*server_side=*/true);
        try {
            status = handler(ctx, bidi_stream);
        } catch (const std::exception& e) {
            spdlog::error(
                "yuzu::transport[msquic]: bidi handler raised std::exception "
                "— type={} what={}",
                typeid(e).name(), e.what());
            status = Status{StatusCode::Internal,
                            "transport: handler raised exception"};
        } catch (...) {
            spdlog::error(
                "yuzu::transport[msquic]: bidi handler raised non-std "
                "exception");
            status = Status{StatusCode::Internal,
                            "transport: handler raised non-std exception"};
        }
        // Emit the trailer + FIN with the handler's RETURN status BEFORE
        // bidi_stream destructs, so the dtor sees wire_fin_sent and
        // skips its abort path.
        send_server_trailer_and_fin(*bidi_state, status);
    }
    // bidi_stream destructed cleanly. `keep` is dropped on return —
    // the ServerStreamCall stays alive while the listener's
    // live_streams_ holds a ref (until SHUTDOWN_COMPLETE untracks).
}

}  // namespace

// ── msquic callback trampolines ──────────────────────────────────────────────

QUIC_STATUS QUIC_API msquic_stream_callback(HQUIC stream, void* ctx,
                                            QUIC_STREAM_EVENT* ev) {
    auto* call = static_cast<ServerStreamCall*>(ctx);
    switch (ev->Type) {
        case QUIC_STREAM_EVENT_RECEIVE: {
            const bool fin =
                (ev->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) != 0;
            for (uint32_t i = 0; i < ev->RECEIVE.BufferCount; ++i) {
                const auto& b = ev->RECEIVE.Buffers[i];
                StatusCode sc = call->decoder.feed(std::string_view{
                    reinterpret_cast<const char*>(b.Buffer), b.Length});
                if (sc != StatusCode::Ok) {
                    spdlog::warn(
                        "yuzu::transport[msquic]: inbound framing error, "
                        "aborting stream");
                    MsQuicApi::instance().api()->StreamShutdown(
                        stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
                        map_decoder_error_to_quic(sc));
                    if (call->bidi_state) {
                        feed_bidi_error(*call->bidi_state,
                                        Status{StatusCode::DataLoss,
                                               "transport: inbound framing error"});
                    }
                    call->phase = ServerStreamCall::Phase::Done;
                    return QUIC_STATUS_SUCCESS;
                }
            }
            // Drain whatever whole frames are now available. Bidi keeps
            // draining (each frame routes into bidi_state); unary breaks
            // out after the request frame is submitted to the worker.
            for (;;) {
                if (call->phase == ServerStreamCall::Phase::Done ||
                    call->phase == ServerStreamCall::Phase::Dispatched) {
                    break;
                }
                auto frame = call->decoder.next_frame();
                if (!frame) break;

                if (call->phase == ServerStreamCall::Phase::AwaitingHello) {
                    pb::HandshakeHello hello;
                    if (!hello.ParseFromString(*frame) ||
                        !method_name_well_formed(hello.method())) {
                        send_trailing_status(
                            call,
                            Status{StatusCode::InvalidArgument,
                                   "transport: malformed HandshakeHello"});
                        call->phase = ServerStreamCall::Phase::Done;
                        break;
                    }
                    // Populate the CallContext from the hello. The
                    // deadline (#376 PR 3 increment 4) is an absolute
                    // system-clock millisecond timestamp; convert to a
                    // remaining-millis duration the handler can pass to
                    // BidiStream::read/write. If the deadline has
                    // already passed by the time we see the hello,
                    // reject immediately with DeadlineExceeded — no
                    // handler dispatch.
                    for (const auto& [k, v] : hello.metadata()) {
                        call->ctx.metadata.emplace(k, v);
                    }
                    if (hello.deadline_unix_millis() != 0) {
                        const auto now_ms =
                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
                        const auto remaining_ms =
                            static_cast<std::int64_t>(
                                hello.deadline_unix_millis()) -
                            now_ms;
                        if (remaining_ms <= 0) {
                            send_trailing_status(
                                call,
                                Status{StatusCode::DeadlineExceeded,
                                       "transport: deadline expired before "
                                       "dispatch"});
                            call->phase = ServerStreamCall::Phase::Done;
                            break;
                        }
                        call->ctx.deadline =
                            std::chrono::milliseconds(remaining_ms);
                    }
                    // Resolve the method (strip an optional leading '/').
                    std::string method = hello.method();
                    if (!method.empty() && method.front() == '/') {
                        method.erase(0, 1);
                    }
                    call->listener->dispatch_stream_call(call, method);
                    // dispatch_stream_call sets phase to AwaitingRequest
                    // (unary), Bidi, or Done (rejected / unimplemented).
                } else if (call->phase ==
                           ServerStreamCall::Phase::AwaitingRequest) {
                    if (call->is_unary) {
                        auto keep = call->self.lock();
                        if (!keep) {
                            call->phase = ServerStreamCall::Phase::Done;
                            break;
                        }
                        std::string request_bytes = std::move(*frame);
                        bool submitted = call->listener->listener_submit(
                            [keep, request_bytes =
                                       std::move(request_bytes)]() mutable {
                                run_unary_handler(keep,
                                                  std::move(request_bytes));
                            });
                        if (!submitted) {
                            send_trailing_status(
                                call,
                                Status{StatusCode::Unavailable,
                                       "transport: listener shutting down"});
                        }
                        call->phase = ServerStreamCall::Phase::Dispatched;
                    }
                } else if (call->phase ==
                           ServerStreamCall::Phase::Bidi) {
                    if (call->bidi_state) {
                        feed_bidi_frame(*call->bidi_state, std::move(*frame));
                    }
                }
            }
            // Honour the FIN flag if it rode in on this RECEIVE event —
            // for bidi the handler's read() needs to know the peer is
            // done (PEER_SEND_SHUTDOWN below covers the separate-event
            // path).
            if (fin && call->phase == ServerStreamCall::Phase::Bidi &&
                call->bidi_state) {
                feed_bidi_fin(*call->bidi_state);
            }
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_STREAM_EVENT_SEND_COMPLETE: {
            delete static_cast<SendBuf*>(ev->SEND_COMPLETE.ClientContext);
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            // Peer half-closed its send direction. For unary this is
            // the expected close after the request frame. For bidi the
            // handler's read() needs to wake — feed_bidi_fin parses any
            // pending lookahead frame as the TrailingStatus.
            if (call->phase == ServerStreamCall::Phase::Bidi &&
                call->bidi_state) {
                feed_bidi_fin(*call->bidi_state);
            }
            return QUIC_STATUS_SUCCESS;

        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
            MsquicServerListener* listener = call->listener;
            // Set stream_closed and StreamClose under call->mtx so a
            // worker thread mid-send_frame/abort_stream either completes
            // its StreamSend before the handle is closed or observes
            // stream_closed and no-ops (governance UP-1 / CH-1).
            {
                std::lock_guard<std::mutex> lock(call->mtx);
                call->stream_closed = true;
                MsQuicApi::instance().api()->StreamClose(stream);
            }
            // For bidi, also close the bidi-state side and synthesise a
            // final status if the peer never delivered a clean trailer
            // (otherwise final_status() blocks forever). Same UP-1 lock
            // discipline — write under bidi_state->mtx.
            if (call->bidi_state) {
                {
                    std::lock_guard<std::mutex> lock(call->bidi_state->mtx);
                    call->bidi_state->stream_closed = true;
                }
                feed_bidi_error(*call->bidi_state,
                                Status{StatusCode::Cancelled,
                                       "transport: stream closed"});
            }
            // Dropping the registry's shared_ptr; if a worker still holds
            // one the ServerStreamCall outlives this call until it
            // returns. After SHUTDOWN_COMPLETE msquic delivers no further
            // events for this stream.
            listener->untrack_stream(stream);
            return QUIC_STATUS_SUCCESS;
        }

        default:
            return QUIC_STATUS_SUCCESS;
    }
}

QUIC_STATUS QUIC_API msquic_conn_callback(HQUIC conn, void* ctx,
                                          QUIC_CONNECTION_EVENT* ev) {
    auto* listener = static_cast<MsquicServerListener*>(ctx);
    const auto* api = MsQuicApi::instance().api();
    switch (ev->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            return QUIC_STATUS_SUCCESS;

        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
            HQUIC stream = ev->PEER_STREAM_STARTED.Stream;
            std::size_t max_frame = listener->stream_max_frame();
            auto call = std::make_shared<ServerStreamCall>(max_frame);
            call->listener = listener;
            call->stream   = stream;
            call->self     = call;
            listener->track_stream(stream, call);
            api->SetCallbackHandler(
                stream, reinterpret_cast<void*>(msquic_stream_callback),
                call.get());
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            // ConnectionClose frees the handle; untrack_connection then
            // removes the (now-stale) handle value from the registry and
            // wakes a draining shutdown(). After SHUTDOWN_COMPLETE msquic
            // delivers no further events for this connection.
            api->ConnectionClose(conn);
            listener->untrack_connection(conn);
            return QUIC_STATUS_SUCCESS;

        default:
            return QUIC_STATUS_SUCCESS;
    }
}

QUIC_STATUS QUIC_API msquic_listener_callback(HQUIC /*listener_handle*/,
                                              void* ctx,
                                              QUIC_LISTENER_EVENT* ev) {
    auto* listener = static_cast<MsquicServerListener*>(ctx);
    const auto* api = MsQuicApi::instance().api();
    switch (ev->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
            HQUIC conn = ev->NEW_CONNECTION.Connection;
            api->SetCallbackHandler(
                conn, reinterpret_cast<void*>(msquic_conn_callback), listener);
            // Track the connection before configuring it so shutdown()
            // can drain it; the conn callback's SHUTDOWN_COMPLETE untracks.
            listener->track_connection(conn);
            return api->ConnectionSetConfiguration(conn,
                                                   listener->configuration_);
        }
        default:
            return QUIC_STATUS_SUCCESS;
    }
}

// ── MsquicServerListener ─────────────────────────────────────────────────────

MsquicServerListener::MsquicServerListener() = default;

MsquicServerListener::~MsquicServerListener() { shutdown(); }

void MsquicServerListener::enforce_method_or_die(const std::string& method) {
    // Registration after start() is a FailedPrecondition contract
    // violation (transport.hpp) and would race dispatch_stream_call's
    // handler-map reads — reject loudly, matching the gRPC backend
    // (governance cons-B1).
    if (started_.load(std::memory_order_acquire)) {
        throw std::logic_error(
            "transport: register_* called after start() (FailedPrecondition)");
    }
    if (!method_name_well_formed(method)) {
        throw std::invalid_argument(
            "transport: malformed RPC method name: " + method);
    }
}

void MsquicServerListener::register_unary(
    std::string method,
    std::function<std::unique_ptr<SerializableMessage>()> request_factory,
    std::function<std::unique_ptr<SerializableMessage>()> response_factory,
    UnaryHandler handler) {
    enforce_method_or_die(method);
    std::lock_guard<std::mutex> lock(mtx_);
    // Duplicate registration is a programming error — reject it loudly
    // rather than silently overwriting via operator[] (governance cons-B2).
    if (unary_handlers_.contains(method) || bidi_handlers_.contains(method)) {
        throw std::invalid_argument(
            "transport: method already registered: " + method);
    }
    unary_handlers_[std::move(method)] = UnaryRegistration{
        std::move(request_factory), std::move(response_factory),
        std::move(handler)};
}

void MsquicServerListener::register_bidi_stream(std::string method,
                                                BidiStreamHandler handler) {
    enforce_method_or_die(method);
    std::lock_guard<std::mutex> lock(mtx_);
    if (unary_handlers_.contains(method) || bidi_handlers_.contains(method)) {
        throw std::invalid_argument(
            "transport: method already registered: " + method);
    }
    bidi_handlers_[std::move(method)] = std::move(handler);
}

std::size_t MsquicServerListener::stream_max_frame() const noexcept {
    return opts_.max_frame_size ? opts_.max_frame_size : kDefaultMaxFrameSize;
}

bool MsquicServerListener::listener_submit(std::function<void()> task) {
    // worker_pool_ is read here from msquic stream-callback threads and
    // moved-out by shutdown() — both under mtx_ (governance UP-6 / CH-2).
    std::lock_guard<std::mutex> lock(mtx_);
    if (!worker_pool_) return false;
    return worker_pool_->submit(std::move(task));
}

void MsquicServerListener::track_stream(
    HQUIC stream, std::shared_ptr<ServerStreamCall> call) {
    std::lock_guard<std::mutex> lock(mtx_);
    live_streams_[stream] = std::move(call);
}

void MsquicServerListener::untrack_stream(HQUIC stream) {
    std::shared_ptr<ServerStreamCall> released;  // freed outside the lock
    {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = live_streams_.find(stream);
        if (it != live_streams_.end()) {
            released = std::move(it->second);
            live_streams_.erase(it);
        }
    }
}

void MsquicServerListener::track_connection(HQUIC conn) {
    std::lock_guard<std::mutex> lock(mtx_);
    live_connections_.insert(conn);
}

void MsquicServerListener::untrack_connection(HQUIC conn) {
    {
        std::lock_guard<std::mutex> lock(mtx_);
        live_connections_.erase(conn);
    }
    // Wake shutdown() if it is waiting for the connection set to drain.
    conn_drain_cv_.notify_all();
}

void MsquicServerListener::dispatch_stream_call(ServerStreamCall* call,
                                                const std::string& method) {
    // Snapshot the handler under mtx_, then release before doing any
    // listener_submit (which also takes mtx_ — avoid the nested lock).
    UnaryRegistration unary_reg;
    BidiStreamHandler bidi_handler;
    enum { Unary, Bidi, Unknown } kind = Unknown;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        auto uit = unary_handlers_.find(method);
        if (uit != unary_handlers_.end()) {
            kind      = Unary;
            unary_reg = uit->second;
        } else {
            auto bit = bidi_handlers_.find(method);
            if (bit != bidi_handlers_.end()) {
                kind         = Bidi;
                bidi_handler = bit->second;
            }
        }
    }

    if (kind == Unary) {
        call->is_unary         = true;
        call->request_factory  = std::move(unary_reg.request_factory);
        call->response_factory = std::move(unary_reg.response_factory);
        call->unary_handler    = std::move(unary_reg.handler);
        call->phase            = ServerStreamCall::Phase::AwaitingRequest;
        return;
    }
    if (kind == Bidi) {
        call->bidi_handler        = std::move(bidi_handler);
        call->bidi_state          = std::make_shared<BidiStreamState>();
        call->bidi_state->stream  = call->stream;
        call->bidi_state->self    = call->bidi_state;
        call->phase               = ServerStreamCall::Phase::Bidi;

        auto keep = call->self.lock();
        if (!keep) {
            call->phase = ServerStreamCall::Phase::Done;
            return;
        }
        // Snapshot what the worker needs and submit. The worker runs the
        // BidiStreamHandler with a server-side MsquicBidiStream wrapping
        // the bidi_state, then emits the trailer + FIN with the handler's
        // RETURN status (run_bidi_handler).
        auto bidi_state_for_worker = call->bidi_state;
        auto handler_copy          = call->bidi_handler;
        CallContext ctx_copy       = call->ctx;
        bool submitted = listener_submit(
            [keep, bidi_state_for_worker, handler_copy,
             ctx_copy = std::move(ctx_copy)]() mutable {
                run_bidi_handler(std::move(keep),
                                 std::move(bidi_state_for_worker),
                                 std::move(handler_copy),
                                 std::move(ctx_copy));
            });
        if (!submitted) {
            // Pool gone — listener shutting down. Emit Unavailable on
            // the bidi state so any future read on the (yet to be
            // constructed) MsquicBidiStream sees a final status.
            feed_bidi_error(*call->bidi_state,
                            Status{StatusCode::Unavailable,
                                   "transport: listener shutting down"});
            send_trailing_status(
                call, Status{StatusCode::Unavailable,
                             "transport: listener shutting down"});
            call->phase = ServerStreamCall::Phase::Done;
        }
        return;
    }

    // Unknown method — detail string matches the gRPC backend verbatim
    // so operators grepping status records see one string (cons-S3).
    send_trailing_status(
        call, Status{StatusCode::Unimplemented,
                     "transport: method not registered"});
    call->phase = ServerStreamCall::Phase::Done;
}

std::expected<void, Status> MsquicServerListener::start(
    const Endpoint& bind, const Credentials& creds,
    const ListenerOptions& opts) {
    auto& api_handle = MsQuicApi::instance();
    if (!api_handle.ok()) {
        return std::unexpected(Status{StatusCode::Internal,
                                      "transport: " + api_handle.init_error()});
    }
    const auto* api = api_handle.api();

    // max_frame_size must not exceed the absolute ceiling (transport.hpp);
    // matches the gRPC backend's start() rejection (governance cons-S1).
    if (opts.max_frame_size > kAbsoluteMaxFrameSize) {
        return std::unexpected(Status{
            StatusCode::InvalidArgument,
            "transport: max_frame_size exceeds kAbsoluteMaxFrameSize"});
    }

    // YUZU_ALLOW_INSECURE_TLS posture gate (#376 PR 3 increment 5).
    if (Status posture = check_insecure_tls_posture(creds, /*client=*/false);
        !posture.ok()) {
        return std::unexpected(posture);
    }

    {
        std::lock_guard<std::mutex> lock(mtx_);
        opts_ = opts;
    }

    // ALPN — full multi-protocol list (#376 PR 3 increment 5). Empty
    // input is promoted to {"yuzu/1"}.
    auto alpn = build_alpn_buffers(creds.alpn_protocols);
    const auto alpn_count = static_cast<uint32_t>(alpn.buffers.size());

    QUIC_SETTINGS settings{};
    settings.IdleTimeoutMs            = 5000;
    settings.IsSet.IdleTimeoutMs      = TRUE;
    settings.PeerBidiStreamCount =
        opts.max_concurrent_streams_per_connection
            ? static_cast<uint16_t>(opts.max_concurrent_streams_per_connection)
            : 128;
    settings.IsSet.PeerBidiStreamCount = TRUE;

    QUIC_STATUS st = api->ConfigurationOpen(
        api_handle.registration(), alpn.buffers.data(), alpn_count, &settings,
        sizeof(settings), nullptr, &configuration_);
    if (QUIC_FAILED(st)) {
        configuration_ = nullptr;
        return std::unexpected(Status{
            StatusCode::Internal,
            "transport: ConfigurationOpen failed " + quic_status_hex(st)});
    }

    // Credential load. INCREMENT-2 SCOPE: server-auth-only TLS via the
    // temp-file path — mTLS / client-cert verification / in-memory PKCS12
    // is increment 5.
    std::string err;
    auto cert_path = write_temp_pem(creds.server_cert_pem, err);
    if (!cert_path) {
        api->ConfigurationClose(configuration_);
        configuration_ = nullptr;
        return std::unexpected(Status{StatusCode::Internal, err});
    }
    auto key_path = write_temp_pem(creds.server_key_pem, err);
    if (!key_path) {
#ifndef _WIN32
        ::unlink(cert_path->c_str());
#endif
        api->ConfigurationClose(configuration_);
        configuration_ = nullptr;
        return std::unexpected(Status{StatusCode::Internal, err});
    }

    QUIC_CERTIFICATE_FILE cert_file{};
    cert_file.PrivateKeyFile  = key_path->c_str();
    cert_file.CertificateFile = cert_path->c_str();
    QUIC_CREDENTIAL_CONFIG cred{};
    cred.Type            = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    cred.Flags           = QUIC_CREDENTIAL_FLAG_NONE;  // server-auth only
    cred.CertificateFile = &cert_file;

    st = api->ConfigurationLoadCredential(configuration_, &cred);
#ifndef _WIN32
    ::unlink(cert_path->c_str());
    ::unlink(key_path->c_str());
#endif
    if (QUIC_FAILED(st)) {
        api->ConfigurationClose(configuration_);
        configuration_ = nullptr;
        return std::unexpected(Status{
            StatusCode::Unauthenticated,
            "transport: ConfigurationLoadCredential failed " +
                quic_status_hex(st)});
    }

    // Worker pool for handler dispatch.
    worker_pool_ = std::make_unique<WorkerPool>(4);

    st = api->ListenerOpen(api_handle.registration(), msquic_listener_callback,
                           this, &listener_);
    if (QUIC_FAILED(st)) {
        listener_ = nullptr;
        worker_pool_.reset();
        api->ConfigurationClose(configuration_);
        configuration_ = nullptr;
        return std::unexpected(Status{
            StatusCode::Internal,
            "transport: ListenerOpen failed " + quic_status_hex(st)});
    }

    QUIC_ADDR addr{};
    if (!make_quic_addr(bind.host, bind.port, addr)) {
        api->ListenerClose(listener_);
        listener_ = nullptr;
        worker_pool_.reset();
        api->ConfigurationClose(configuration_);
        configuration_ = nullptr;
        return std::unexpected(Status{
            StatusCode::InvalidArgument,
            "transport: bind host is not a valid IP literal: " + bind.host});
    }

    st = api->ListenerStart(listener_, alpn.buffers.data(), alpn_count, &addr);
    if (QUIC_FAILED(st)) {
        api->ListenerClose(listener_);
        listener_ = nullptr;
        worker_pool_.reset();
        api->ConfigurationClose(configuration_);
        configuration_ = nullptr;
        return std::unexpected(Status{
            StatusCode::Unavailable,
            "transport: ListenerStart failed " + quic_status_hex(st)});
    }

    // Resolve the bound port (ephemeral when bind.port == 0).
    QUIC_ADDR local{};
    uint32_t local_size = sizeof(local);
    st = api->GetParam(listener_, QUIC_PARAM_LISTENER_LOCAL_ADDRESS,
                       &local_size, &local);
    {
        std::lock_guard<std::mutex> lock(mtx_);
        bound_endpoint_.host = bind.host;  // echo verbatim (wildcard caveat)
        bound_endpoint_.port =
            QUIC_SUCCEEDED(st) ? QuicAddrGetPort(&local) : bind.port;
    }

    started_.store(true, std::memory_order_release);
    spdlog::info("yuzu::transport[msquic]: listening on {}:{}", bind.host,
                 bound_endpoint_.port);
    return {};
}

void MsquicServerListener::wait_for_shutdown() {
    std::unique_lock<std::mutex> lock(mtx_);
    shutdown_cv_.wait(lock, [this] {
        return shutting_down_.load(std::memory_order_acquire);
    });
}

void MsquicServerListener::shutdown() {
    if (shutting_down_.exchange(true, std::memory_order_acq_rel)) {
        return;  // idempotent
    }
    started_.store(false, std::memory_order_release);

    const auto* api = MsQuicApi::instance().api();
    if (api != nullptr && listener_ != nullptr) {
        api->ListenerStop(listener_);
        api->ListenerClose(listener_);
        listener_ = nullptr;
    }

    // Drain every accepted connection before the listener (and its
    // live_streams_ map) is destroyed: ConnectionShutdown initiates the
    // close, each connection's SHUTDOWN_COMPLETE callback runs
    // ConnectionClose + untrack_connection, and we wait for
    // live_connections_ to empty. Without this a late stream callback
    // dereferences a freed ServerStreamCall (governance UP-13 / UP-18 —
    // surfaced as a crash by the B2 per-stream mutex).
    if (api != nullptr) {
        std::vector<HQUIC> conns;
        {
            std::lock_guard<std::mutex> lock(mtx_);
            conns.assign(live_connections_.begin(), live_connections_.end());
        }
        for (HQUIC c : conns) {
            api->ConnectionShutdown(c, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        }
        std::unique_lock<std::mutex> lock(mtx_);
        if (!conn_drain_cv_.wait_for(lock, std::chrono::seconds(10), [this] {
                return live_connections_.empty();
            })) {
            // ConnectionShutdown reliably produces SHUTDOWN_COMPLETE; a
            // 10s no-drain means msquic itself is wedged. Proceeding
            // would let the dtor destroy live_streams_ with a stream
            // callback still in flight — the UP-13 use-after-free. A
            // clean abort beats a UAF (governance Gate-7 re-review).
            spdlog::critical(
                "yuzu::transport[msquic]: {} connection(s) failed to drain "
                "within 10s on shutdown — aborting to avoid use-after-free",
                live_connections_.size());
            std::abort();
        }
    }

    // Join the worker pool after the connections have drained — no
    // further callbacks will submit work. Move worker_pool_ out under
    // mtx_ (listener_submit reads it from callback threads — UP-6) then
    // join the local OUTSIDE the lock.
    std::unique_ptr<WorkerPool> pool;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        pool = std::move(worker_pool_);
    }
    pool.reset();  // joins handler workers
    if (api != nullptr && configuration_ != nullptr) {
        api->ConfigurationClose(configuration_);
        configuration_ = nullptr;
    }
    shutdown_cv_.notify_all();
}

bool MsquicServerListener::is_serving() const noexcept {
    return started_.load(std::memory_order_acquire) &&
           !shutting_down_.load(std::memory_order_acquire);
}

Endpoint MsquicServerListener::bound_endpoint() const noexcept {
    std::lock_guard<std::mutex> lock(mtx_);
    return bound_endpoint_;
}

}  // namespace yuzu::transport::msquic_backend
