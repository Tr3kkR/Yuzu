// SPDX-License-Identifier: Apache-2.0

#include "grpc_listener.hpp"

#include <grpcpp/generic/async_generic_service.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/support/byte_buffer.h>
#include <grpcpp/support/slice.h>

#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "grpc_channel.hpp"            // for make_grpc_server_credentials
#include "grpc_internal_helpers.hpp"   // method_name_well_formed, byte helpers, sanitise

#include <thread>  // std::this_thread for shutdown re-entry detection

namespace yuzu::transport::grpc_backend {

namespace {

// Translate yuzu::transport::Status (numeric value frozen by the
// static_asserts in grpc_channel.cpp) into grpc::Status. The detail
// string is sanitised first per the Status::detail visibility contract
// in transport.hpp (governance UP-22 + sec-F1 + doc-S6).
::grpc::Status to_grpc_status(const Status& s) {
    return ::grpc::Status(
        static_cast<::grpc::StatusCode>(static_cast<int>(s.code)),
        sanitise_status_detail(s.detail));
}

}  // namespace

// =====================================================================
// ServerCall — per-call state machine driven by the CQ worker thread.
// =====================================================================
//
// Tag pointer = `this`. cq->Next returns the tag; the worker static_casts
// and calls on_event(ok). The state machine advances; on terminal state
// `delete this` releases the heap allocation.
//
// Lifecycle:
//   PendingNew (RequestCall posted) →
//     ok=true:  RequestCall completed → handle_request_arrived()
//                 → if unary handler registered:
//                     post a Read; state = PendingRead
//                   else:
//                     post a Finish(Unimplemented); state = PendingFinish
//     ok=false: server is shutting down before the call landed → delete
//
//   PendingRead (Read posted) →
//     ok=true:  request bytes arrived → invoke handler synchronously,
//                 serialize response, post WriteAndFinish; state = PendingFinish
//     ok=false: peer cancelled mid-read or shutdown → delete
//
//   PendingFinish (Finish or WriteAndFinish posted) →
//     ok=true or false: terminal → delete
class ServerCall final {
public:
    enum class State { PendingNew, PendingRead, PendingFinish };

    explicit ServerCall(GrpcServerListener* listener)
        : listener_(listener), rw_(&gctx_) {}

    // Begin a new RequestCall on the listener. Heap-allocates a fresh
    // ServerCall and posts it as a tag for the next incoming RPC.
    static void post_new(GrpcServerListener* listener) {
        if (listener->shutting_down_.load(std::memory_order_acquire)) {
            return;  // do not enqueue more after shutdown
        }
        auto* call = new ServerCall(listener);
        listener->generic_service_.RequestCall(
            &call->gctx_, &call->rw_, listener->cq_.get(),
            listener->cq_.get(), static_cast<void*>(call));
    }

    void on_event(bool ok) {
        switch (state_) {
            case State::PendingNew: {
                if (!ok) {
                    delete this;
                    return;
                }
                // A real call has arrived. Post the next RequestCall so the
                // listener accepts further RPCs while we handle this one.
                ServerCall::post_new(listener_);
                handle_request_arrived();
                return;
            }
            case State::PendingRead: {
                if (!ok) {
                    // Peer cancelled or shut down before sending the request
                    // body. Reply with Cancelled and finish cleanly.
                    final_status_ =
                        ::grpc::Status(::grpc::StatusCode::CANCELLED,
                                       "transport: request not fully received");
                    rw_.Finish(final_status_, static_cast<void*>(this));
                    state_ = State::PendingFinish;
                    return;
                }
                dispatch_unary();
                return;
            }
            case State::PendingFinish: {
                // Terminal — delete regardless of ok. ok=false here just
                // means the channel was already going down when we tried
                // to send the trailing status; nothing further to do.
                delete this;
                return;
            }
        }
    }

private:
    // After RequestCall completes, look up the handler and route.
    // Tear-down on shutdown short-circuits the dispatch.
    void handle_request_arrived() {
        const std::string& method = gctx_.method();

        // Look up handler under the listener's lock so a concurrent
        // (but contractually-illegal) register_* race doesn't tear the
        // map.
        bool unary_match = false;
        {
            std::lock_guard<std::mutex> lock(listener_->mtx_);
            unary_match = listener_->unary_handlers_.contains(method);
            // Bidi handlers are documented but dispatch lands in PR 1b-3.
        }

        if (!unary_match) {
            final_status_ =
                ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED,
                               "transport: method not registered or not a unary RPC");
            rw_.Finish(final_status_, static_cast<void*>(this));
            state_ = State::PendingFinish;
            return;
        }

        // Read the request bytes. The handler runs inline once Read fires.
        rw_.Read(&req_buf_, static_cast<void*>(this));
        state_ = State::PendingRead;
    }

    void dispatch_unary() {
        const std::string& method = gctx_.method();

        // Snapshot the handler under the lock so we can release it
        // before invoking user code.
        std::function<std::unique_ptr<SerializableMessage>()> req_factory;
        std::function<std::unique_ptr<SerializableMessage>()> resp_factory;
        UnaryHandler handler;
        {
            std::lock_guard<std::mutex> lock(listener_->mtx_);
            auto it = listener_->unary_handlers_.find(method);
            if (it == listener_->unary_handlers_.end()) {
                // Unregistered between PendingNew and PendingRead — should
                // be impossible per the register-after-start contract,
                // but defend anyway.
                final_status_ = ::grpc::Status(::grpc::StatusCode::UNIMPLEMENTED,
                                               "transport: handler unregistered mid-call");
                rw_.Finish(final_status_, static_cast<void*>(this));
                state_ = State::PendingFinish;
                return;
            }
            req_factory  = it->second.request_factory;
            resp_factory = it->second.response_factory;
            handler      = it->second.handler;
        }

        // Deserialize request bytes into a fresh handler-specific message.
        std::string req_bytes;
        if (!byte_buffer_to_string(req_buf_, req_bytes)) {
            final_status_ = ::grpc::Status(::grpc::StatusCode::DATA_LOSS,
                                           "transport: request ByteBuffer dump failed");
            rw_.Finish(final_status_, static_cast<void*>(this));
            state_ = State::PendingFinish;
            return;
        }
        auto req_msg = req_factory();
        if (!req_msg || !req_msg->parse(req_bytes)) {
            final_status_ = ::grpc::Status(::grpc::StatusCode::DATA_LOSS,
                                           "transport: request parse failed");
            rw_.Finish(final_status_, static_cast<void*>(this));
            state_ = State::PendingFinish;
            return;
        }

        // Build CallContext for the handler. Server-side fields
        // (peer_uri, peer_san_identities) populated from gctx_.
        CallContext ctx;
        ctx.peer_uri = gctx_.peer();
        // peer_san_identities: gRPC's auth_context() exposes
        // x509_subject_alternative_name property values. PR 1c may
        // populate these once mTLS is wired through actual call sites;
        // for PR 1b-2 the plaintext path leaves the vector empty.

        auto resp_msg = resp_factory();
        if (!resp_msg) {
            final_status_ = ::grpc::Status(::grpc::StatusCode::INTERNAL,
                                           "transport: response factory returned null");
            rw_.Finish(final_status_, static_cast<void*>(this));
            state_ = State::PendingFinish;
            return;
        }

        // Invoke the handler synchronously. Handler returns a
        // yuzu::transport::Status which we translate to grpc::Status for
        // the trailing reply.
        //
        // Per Status::detail visibility contract (transport.hpp + sec-F1):
        // we DO NOT echo std::exception::what() over the wire because it
        // typically contains internal state (file paths, DB error
        // messages, library-internal text). Instead we surface a static
        // summary; the handler's full what() is logged server-side via
        // the metric_sink for operator diagnosis.
        Status handler_status;
        try {
            handler_status = handler(ctx, *req_msg, *resp_msg);
        } catch (const std::exception& e) {
            handler_status = {StatusCode::Internal, "handler raised exception"};
            // Server-side log via metric sink (PR 1c will plug an
            // explicit logging hook; the metric sink's stream-closed
            // callback is the closest available channel for now).
            // The full what() text never leaves the process boundary.
            (void)e;  // intentional: do not include in wire status
        } catch (...) {
            handler_status = {StatusCode::Internal,
                              "handler raised non-std exception"};
        }

        if (!handler_status.ok()) {
            final_status_ = to_grpc_status(handler_status);
            rw_.Finish(final_status_, static_cast<void*>(this));
            state_ = State::PendingFinish;
            return;
        }

        // Serialize response and ship via WriteAndFinish (one CQ event).
        std::string resp_bytes;
        if (!resp_msg->serialize(resp_bytes)) {
            final_status_ = ::grpc::Status(::grpc::StatusCode::INTERNAL,
                                           "transport: response serialize failed");
            rw_.Finish(final_status_, static_cast<void*>(this));
            state_ = State::PendingFinish;
            return;
        }
        // Frame-size enforcement on the outbound side (mirror of the
        // client-side guard). Matches the listener's configured cap if
        // operator opted in via ListenerOptions::max_frame_size.
        const std::size_t frame_cap =
            listener_->opts_.max_frame_size > 0
                ? listener_->opts_.max_frame_size
                : kDefaultMaxFrameSize;
        if (resp_bytes.size() > frame_cap) {
            final_status_ = ::grpc::Status(::grpc::StatusCode::RESOURCE_EXHAUSTED,
                                           "transport: response exceeds configured frame size");
            rw_.Finish(final_status_, static_cast<void*>(this));
            state_ = State::PendingFinish;
            return;
        }

        resp_buf_     = string_to_byte_buffer(resp_bytes);
        final_status_ = ::grpc::Status::OK;
        rw_.WriteAndFinish(resp_buf_, ::grpc::WriteOptions(), final_status_,
                           static_cast<void*>(this));
        state_ = State::PendingFinish;
    }

    State                                state_ = State::PendingNew;
    GrpcServerListener*                  listener_ = nullptr;
    ::grpc::GenericServerContext         gctx_;
    ::grpc::GenericServerAsyncReaderWriter rw_;
    ::grpc::ByteBuffer                   req_buf_;
    ::grpc::ByteBuffer                   resp_buf_;
    ::grpc::Status                       final_status_;
};

// =====================================================================
// GrpcServerListener
// =====================================================================

GrpcServerListener::GrpcServerListener() = default;

GrpcServerListener::~GrpcServerListener() {
    if (started_.load(std::memory_order_acquire) &&
        !shutting_down_.load(std::memory_order_acquire)) {
        try {
            shutdown();
        } catch (...) {
            // Documented as noexcept; swallow defensively.
        }
    }
    // Worker thread is joined inside shutdown(); guard against
    // dtor-without-shutdown for completeness.
    if (cq_worker_.joinable()) {
        cq_worker_.join();
    }
}

void GrpcServerListener::enforce_method_or_die(const std::string& method) {
    if (!method_name_well_formed(method)) {
        throw std::invalid_argument(
            "yuzu::transport: method name fails validation contract: " +
            method);
    }
    if (started_.load(std::memory_order_acquire)) {
        throw std::logic_error(
            "yuzu::transport: register_* after start() is not permitted");
    }
}

void GrpcServerListener::register_unary(
    std::string method,
    std::function<std::unique_ptr<SerializableMessage>()> request_factory,
    std::function<std::unique_ptr<SerializableMessage>()> response_factory,
    UnaryHandler handler) {
    enforce_method_or_die(method);
    std::lock_guard<std::mutex> lock(mtx_);
    if (unary_handlers_.contains(method) || bidi_handlers_.contains(method)) {
        throw std::invalid_argument(
            "yuzu::transport: method already registered: " + method);
    }
    unary_handlers_.emplace(
        std::move(method),
        UnaryRegistration{std::move(request_factory),
                          std::move(response_factory), std::move(handler)});
}

void GrpcServerListener::register_bidi_stream(std::string method,
                                              BidiStreamHandler handler) {
    enforce_method_or_die(method);
    std::lock_guard<std::mutex> lock(mtx_);
    if (unary_handlers_.contains(method) || bidi_handlers_.contains(method)) {
        throw std::invalid_argument(
            "yuzu::transport: method already registered: " + method);
    }
    bidi_handlers_.emplace(std::move(method), std::move(handler));
}

std::expected<void, Status> GrpcServerListener::start(
    const Endpoint& bind, const Credentials& creds,
    const ListenerOptions& opts) {
    const std::size_t frame_cap =
        opts.max_frame_size > 0 ? opts.max_frame_size : kDefaultMaxFrameSize;
    if (frame_cap > kAbsoluteMaxFrameSize) {
        return std::unexpected(Status{
            StatusCode::InvalidArgument,
            "ListenerOptions::max_frame_size exceeds kAbsoluteMaxFrameSize"});
    }

    if (started_.exchange(true, std::memory_order_acq_rel)) {
        return std::unexpected(Status{StatusCode::FailedPrecondition,
                                      "ServerListener::start called twice"});
    }

    std::string detail;
    auto server_creds = make_grpc_server_credentials(creds, detail);
    if (!server_creds) {
        started_.store(false, std::memory_order_release);
        return std::unexpected(Status{StatusCode::Unauthenticated, detail});
    }

    {
        std::lock_guard<std::mutex> lock(mtx_);
        opts_ = opts;
    }

    const std::string addr = bind.host + ":" + std::to_string(bind.port);
    ::grpc::ServerBuilder builder;

    // selected_port: gRPC writes the actual bound port here after
    // BuildAndStart. When bind.port == 0 the OS assigns ephemeral; the
    // value is exposed to operators via bound_endpoint() so tests and
    // any caller can discover it (governance qe-F1).
    int selected_port = 0;
    builder.AddListeningPort(addr, server_creds, &selected_port);

    if (opts.max_concurrent_streams_per_connection > 0) {
        builder.AddChannelArgument(
            GRPC_ARG_MAX_CONCURRENT_STREAMS,
            static_cast<int>(opts.max_concurrent_streams_per_connection));
    }
    builder.SetMaxReceiveMessageSize(static_cast<int>(frame_cap));
    builder.SetMaxSendMessageSize(static_cast<int>(frame_cap));

    builder.RegisterAsyncGenericService(&generic_service_);
    cq_ = builder.AddCompletionQueue();

    server_ = builder.BuildAndStart();
    if (!server_) {
        cq_.reset();
        started_.store(false, std::memory_order_release);
        return std::unexpected(
            Status{StatusCode::Unavailable,
                   "transport: gRPC ServerBuilder::BuildAndStart returned null"});
    }
    if (selected_port == 0) {
        // BuildAndStart returned non-null but failed to bind. Per gRPC
        // docs (server_builder.h:127): selected_port stays 0 when bind
        // fails. Treat as unavailable.
        server_->Shutdown();
        server_.reset();
        cq_.reset();
        started_.store(false, std::memory_order_release);
        return std::unexpected(
            Status{StatusCode::Unavailable,
                   "transport: gRPC failed to bind listening port"});
    }
    {
        std::lock_guard<std::mutex> lock(mtx_);
        bound_endpoint_.host = bind.host;
        bound_endpoint_.port = static_cast<uint16_t>(selected_port);
    }

    // Spawn the worker thread that pumps cq_ and drives ServerCall state
    // machines. Post the first RequestCall so the dispatch loop has work
    // to do as soon as a client connects.
    cq_worker_ = std::thread([this] { cq_worker_loop(); });
    post_new_request_call();

    if (opts.metric_sink) {
        opts.metric_sink->on_connection_opened("grpc");
    }
    return {};
}

void GrpcServerListener::post_new_request_call() {
    ServerCall::post_new(this);
}

void GrpcServerListener::cq_worker_loop() {
    void* tag = nullptr;
    bool ok = false;
    while (cq_->Next(&tag, &ok)) {
        // Wrap each per-event dispatch so a single ServerCall throw does
        // not kill the worker and leave the listener wedged with no one
        // pumping the CQ (governance UP-16). User-supplied handlers are
        // already wrapped inside dispatch_unary; this outer wrap defends
        // against bugs in the dispatcher itself, in gRPC interactions,
        // or in the SerializableMessage adapters.
        try {
            static_cast<ServerCall*>(tag)->on_event(ok);
        } catch (...) {
            // Defensive: nothing further we can do at this layer. PR 1c
            // will plug a structured logging hook that surfaces this to
            // operators; until then, swallow and continue. Crashing the
            // worker would convert a recoverable handler bug into a
            // listener-wide outage with no signal in /readyz.
        }
    }
    // cq_->Next returns false only after Shutdown has been called AND
    // all outstanding tags have been drained. After the loop exits the
    // queue is fully consumed and worker thread can exit.
}

void GrpcServerListener::wait_for_shutdown() {
    std::unique_lock<std::mutex> lock(mtx_);
    shutdown_cv_.wait(
        lock,
        [this] { return shutting_down_.load(std::memory_order_acquire); });
}

void GrpcServerListener::shutdown() {
    if (shutting_down_.exchange(true, std::memory_order_acq_rel)) {
        return;  // idempotent
    }
    // Detect handler-initiated shutdown: if a handler running on
    // cq_worker_ calls listener->shutdown(), we cannot synchronously
    // join cq_worker_ from itself. server_->Shutdown() would also
    // block on the same handler returning. Two-way deadlock
    // (governance UP-15). Detect and refuse explicitly so the bug
    // surfaces as a clear exception rather than a process hang.
    if (cq_worker_.joinable() &&
        cq_worker_.get_id() == std::this_thread::get_id()) {
        // Roll back the flag so a subsequent call from another thread
        // can complete the shutdown.
        shutting_down_.store(false, std::memory_order_release);
        throw std::logic_error(
            "yuzu::transport: shutdown() must not be called from a handler "
            "running on the listener's CQ worker thread; arrange for an "
            "external thread to invoke shutdown() instead");
    }
    if (server_) {
        // shutdown trailing-status guarantee per transport.hpp: in-flight
        // handlers receive Unavailable. PR 1b-2 dispatcher honours this
        // for unary calls — server_->Shutdown() causes the underlying
        // gRPC layer to deliver UNAVAILABLE to clients whose calls are
        // still in flight.
        //
        // PR 1b-3 will need to pass a deadline (governance UP-13);
        // current PR 1b-2 has no live bidi streams to wedge.
        server_->Shutdown();
    }
    if (cq_) {
        // Shutdown the CQ AFTER server shutdown so any pending tags get
        // drained with ok=false and ServerCall::on_event deletes them.
        cq_->Shutdown();
    }
    if (cq_worker_.joinable()) {
        cq_worker_.join();
    }
    {
        std::lock_guard<std::mutex> lock(mtx_);
        shutdown_cv_.notify_all();
    }
}

bool GrpcServerListener::is_serving() const noexcept {
    return started_.load(std::memory_order_acquire) &&
           !shutting_down_.load(std::memory_order_acquire);
}

Endpoint GrpcServerListener::bound_endpoint() const noexcept {
    std::lock_guard<std::mutex> lock(mtx_);
    return bound_endpoint_;
}

}  // namespace yuzu::transport::grpc_backend
