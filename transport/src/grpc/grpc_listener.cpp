// SPDX-License-Identifier: Apache-2.0

#include "grpc_listener.hpp"

#include <grpcpp/generic/async_generic_service.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/support/byte_buffer.h>
#include <grpcpp/support/slice.h>

#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "grpc_channel.hpp"            // for make_grpc_server_credentials
#include "grpc_internal_helpers.hpp"   // method_name_well_formed, byte helpers, sanitise

#include <spdlog/spdlog.h>

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

// Build a transport-internal grpc::Status without going through a
// yuzu::transport::Status round-trip. Every transport-internal Status
// emitted from the dispatcher MUST go through this helper so the
// outbound scrub contract holds across all 8+ construction sites
// (governance round 5 cons-G4-1).
::grpc::Status make_wire_status(StatusCode code, std::string_view detail) {
    return ::grpc::Status(
        static_cast<::grpc::StatusCode>(static_cast<int>(code)),
        sanitise_status_detail(detail));
}

}  // namespace

// =====================================================================
// ServerCall — per-call state machine driven by the CQ worker thread.
// =====================================================================
//
// One ServerCall instance is heap-allocated per RequestCall posted to
// the AsyncGenericService. After the RequestCall completes (an actual
// RPC arrived), the call dispatches to either the unary or the bidi
// path based on which handler matches the method name.
//
// Tag dispatch: the ServerCall itself is a CqTag (handles the start /
// RequestCall and the unary path's PendingRead/PendingFinish). For the
// bidi path, four sub-tag CqTag members route to dedicated callbacks
// so the read/write/finish completions can be told apart.
//
// Lifetime: `delete this` in the terminal branches of on_event /
// on_bidi_finish releases the heap allocation. `final_status_` and
// the bidi sub-tag members live inside ServerCall so they outlive the
// async ops by construction.
class ServerCall final : public CqTag {
public:
    enum class State {
        PendingNew,           // RequestCall posted
        UnaryPendingRead,     // unary: Read posted
        UnaryPendingFinish,   // unary: Finish/WriteAndFinish posted
        BidiActive,           // bidi: handler thread running
        BidiPendingFinish,    // bidi: Finish posted, waiting for CQ
    };

    explicit ServerCall(GrpcServerListener* listener)
        : listener_(listener),
          rw_(&gctx_),
          read_tag_{this},
          write_tag_{this},
          finish_tag_{this} {}

    static void post_new(GrpcServerListener* listener) {
        if (listener->shutting_down_.load(std::memory_order_acquire)) {
            return;  // do not enqueue more after shutdown
        }
        auto* call = new ServerCall(listener);
        listener->generic_service_.RequestCall(
            &call->gctx_, &call->rw_, listener->cq_.get(),
            listener->cq_.get(), static_cast<CqTag*>(call));
    }

    void on_event(bool ok) override {
        switch (state_) {
            case State::PendingNew: {
                if (!ok) {
                    delete this;
                    return;
                }
                ServerCall::post_new(listener_);
                handle_request_arrived();
                return;
            }
            case State::UnaryPendingRead: {
                if (!ok) {
                    final_status_ = make_wire_status(
                        StatusCode::Cancelled,
                        "transport: request not fully received");
                    rw_.Finish(final_status_, static_cast<CqTag*>(this));
                    state_ = State::UnaryPendingFinish;
                    return;
                }
                dispatch_unary();
                return;
            }
            case State::UnaryPendingFinish: {
                delete this;
                return;
            }
            case State::BidiActive:
            case State::BidiPendingFinish:
                // ServerCall::on_event handles only the ServerCall
                // base-tag; bidi sub-tag completions arrive via
                // {read,write,finish}_tag_->on_event.
                spdlog::error(
                    "yuzu::transport: ServerCall base-tag fired in bidi "
                    "state — programming error");
                return;
        }
    }

    // ---- Bidi sub-tag callbacks --------------------------------------
    // Each is dispatched by a distinct CqTag member so the CQ event
    // identifies which operation completed. All run on the cq_worker
    // thread; they signal the handler thread via bidi_cv_.

    void on_bidi_read(bool ok) {
        {
            std::lock_guard<std::mutex> lock(bidi_mtx_);
            bidi_read_done_ = ok;
        }
        bidi_cv_.notify_all();
    }

    void on_bidi_write(bool ok) {
        {
            std::lock_guard<std::mutex> lock(bidi_mtx_);
            bidi_write_done_ = ok;
        }
        bidi_cv_.notify_all();
    }

    void on_bidi_finish(bool /*ok*/) {
        // Terminal for the bidi path. The handler thread has already
        // returned (it scheduled Finish before exit); join it then
        // self-delete.
        if (handler_thread_.joinable()) {
            handler_thread_.join();
        }
        delete this;
    }

private:
    // Bidi sub-tag — each one is a distinct CqTag whose pointer the
    // gRPC CQ uses to identify which operation completed.
    struct ReadTag final : CqTag {
        ServerCall* parent;
        explicit ReadTag(ServerCall* p) : parent(p) {}
        void on_event(bool ok) override { parent->on_bidi_read(ok); }
    };
    struct WriteTag final : CqTag {
        ServerCall* parent;
        explicit WriteTag(ServerCall* p) : parent(p) {}
        void on_event(bool ok) override { parent->on_bidi_write(ok); }
    };
    struct FinishTag final : CqTag {
        ServerCall* parent;
        explicit FinishTag(ServerCall* p) : parent(p) {}
        void on_event(bool ok) override { parent->on_bidi_finish(ok); }
    };

    // Server-side BidiStream surface. The handler thread calls into
    // these methods; they post gRPC async ops on rw_ using the parent
    // ServerCall's sub-tags and block on bidi_cv_ until the cq_worker
    // delivers the matching event.
    //
    // Threading contract per transport.hpp: single-reader + single-
    // writer concurrent. We rely on the caller to honour that; the
    // bidi_mtx_ + bidi_cv_ pair tolerates one in-flight read and one
    // in-flight write at a time.
    class ServerBidiStream final : public BidiStream {
    public:
        explicit ServerBidiStream(ServerCall* call) : call_(call) {}

        bool write(const SerializableMessage& msg) override {
            std::string bytes;
            if (!msg.serialize(bytes)) return false;
            const std::size_t cap =
                call_->listener_->opts_.max_frame_size > 0
                    ? call_->listener_->opts_.max_frame_size
                    : kDefaultMaxFrameSize;
            if (bytes.size() > cap) return false;

            std::unique_lock<std::mutex> lock(call_->bidi_mtx_);
            if (call_->bidi_cancelled_) return false;
            call_->bidi_write_done_.reset();
            call_->bidi_write_buf_ = string_to_byte_buffer(bytes);
            call_->rw_.Write(call_->bidi_write_buf_,
                             static_cast<CqTag*>(&call_->write_tag_));
            call_->bidi_cv_.wait(lock, [this] {
                return call_->bidi_write_done_.has_value() ||
                       call_->bidi_cancelled_;
            });
            if (call_->bidi_cancelled_) return false;
            const bool ok = *call_->bidi_write_done_;
            if (ok && call_->listener_->opts_.metric_sink) {
                call_->listener_->opts_.metric_sink->on_bytes_sent(
                    "grpc", bytes.size());
            }
            return ok;
        }

        bool read(SerializableMessage& msg) override {
            std::unique_lock<std::mutex> lock(call_->bidi_mtx_);
            if (call_->bidi_cancelled_) return false;
            call_->bidi_read_done_.reset();
            call_->bidi_read_buf_.Clear();
            call_->rw_.Read(&call_->bidi_read_buf_,
                            static_cast<CqTag*>(&call_->read_tag_));
            call_->bidi_cv_.wait(lock, [this] {
                return call_->bidi_read_done_.has_value() ||
                       call_->bidi_cancelled_;
            });
            if (call_->bidi_cancelled_) return false;
            if (!*call_->bidi_read_done_) return false;  // peer half-close
            std::string bytes;
            if (!byte_buffer_to_string(call_->bidi_read_buf_, bytes)) {
                return false;
            }
            const std::size_t cap =
                call_->listener_->opts_.max_frame_size > 0
                    ? call_->listener_->opts_.max_frame_size
                    : kDefaultMaxFrameSize;
            if (bytes.size() > cap) {
                // Frame exceeds configured cap — reject as DataLoss-class
                // failure. transport.hpp parse() contract: false ⇒ stream
                // is fatally corrupt; handler exits its read loop.
                return false;
            }
            if (call_->listener_->opts_.metric_sink) {
                call_->listener_->opts_.metric_sink->on_bytes_received(
                    "grpc", bytes.size());
            }
            return msg.parse(bytes);
        }

        void writes_done() override {
            // Server-side: writes_done() is implicit — the trailing
            // status + half-close are emitted by the dispatcher's
            // Finish() call after the handler returns. No-op here.
        }

        Status final_status() override {
            // Server-side: handlers don't normally call final_status()
            // on their own stream. Return Ok with no detail for parity
            // with the BidiStream contract.
            return Status{StatusCode::Ok, ""};
        }

        const std::map<std::string, std::string>& trailing_metadata()
            const override {
            static const std::map<std::string, std::string> empty;
            return empty;
        }

        void cancel() override {
            {
                std::lock_guard<std::mutex> lock(call_->bidi_mtx_);
                call_->bidi_cancelled_ = true;
            }
            call_->bidi_cv_.notify_all();
            call_->gctx_.TryCancel();
        }

    private:
        ServerCall* call_;
    };

    void handle_request_arrived() {
        const std::string& method = gctx_.method();

        bool unary_match = false;
        bool bidi_match = false;
        {
            std::lock_guard<std::mutex> lock(listener_->mtx_);
            unary_match = listener_->unary_handlers_.contains(method);
            bidi_match = listener_->bidi_handlers_.contains(method);
        }

        if (unary_match) {
            rw_.Read(&req_buf_, static_cast<CqTag*>(this));
            state_ = State::UnaryPendingRead;
            return;
        }
        if (bidi_match) {
            dispatch_bidi();
            return;
        }

        final_status_ = make_wire_status(
            StatusCode::Unimplemented,
            "transport: method not registered");
        rw_.Finish(final_status_, static_cast<CqTag*>(this));
        state_ = State::UnaryPendingFinish;
    }

    void dispatch_bidi() {
        const std::string& method = gctx_.method();

        BidiStreamHandler handler;
        {
            std::lock_guard<std::mutex> lock(listener_->mtx_);
            auto it = listener_->bidi_handlers_.find(method);
            if (it == listener_->bidi_handlers_.end()) {
                final_status_ = make_wire_status(
                    StatusCode::Unimplemented,
                    "transport: bidi handler unregistered mid-call");
                rw_.Finish(final_status_, static_cast<CqTag*>(this));
                state_ = State::UnaryPendingFinish;
                return;
            }
            handler = it->second;
        }

        bidi_stream_  = std::make_unique<ServerBidiStream>(this);
        method_cache_ = method;  // copy out; gctx_ stays valid for lifetime

        // Dispatcher thread: invokes the user handler with the bidi
        // surface. Once the handler returns, schedule Finish via
        // finish_tag_; the cq_worker then joins this thread and
        // self-deletes the ServerCall.
        //
        // Lifetime invariant (governance UP-1): std::thread construction
        // can throw on resource exhaustion (EAGAIN, RLIMIT_NPROC). If we
        // set state_ = BidiActive BEFORE the thread spawn, a throwing
        // ctor leaves the call in BidiActive with no thread, no Finish
        // ever scheduled, and `delete this` never invoked — leaking
        // ServerCall and hanging the peer until deadline. Order
        // therefore matters: state_ is bumped to BidiActive only inside
        // the try-block AFTER successful std::thread construction. On
        // failure, fall back to the UnaryPendingFinish path with
        // StatusCode::Internal so the cq_worker reaps via the existing
        // Finish-tag completion.
        try {
            handler_thread_ = std::thread([this, h = std::move(handler)]() mutable {
            CallContext ctx;
            ctx.peer_uri = gctx_.peer();

            Status handler_status;
            try {
                handler_status = h(ctx, *bidi_stream_);
            } catch (const std::exception& e) {
                handler_status = {StatusCode::Internal,
                                  "handler raised exception"};
                spdlog::error(
                    "yuzu::transport: bidi handler raised std::exception in "
                    "{} — type={} what={}",
                    method_cache_, typeid(e).name(),
                    sanitise_status_detail(e.what()));
                if (listener_->opts_.metric_sink) {
                    listener_->opts_.metric_sink->on_unexpected_dispatch_throw(
                        "grpc", method_cache_, "std_exception");
                }
            } catch (...) {
                handler_status = {StatusCode::Internal,
                                  "handler raised non-std exception"};
                spdlog::error(
                    "yuzu::transport: bidi handler raised non-std exception "
                    "in {}", method_cache_);
                if (listener_->opts_.metric_sink) {
                    listener_->opts_.metric_sink->on_unexpected_dispatch_throw(
                        "grpc", method_cache_, "non_std_exception");
                }
            }

            // Schedule Finish on the cq_worker. After this, no further
            // events arrive on the bidi sub-tags except finish_tag_.
            // The dispatcher thread exits; the cq_worker's
            // on_bidi_finish will join() this thread before delete this.
            final_status_ = to_grpc_status(handler_status);
            state_        = State::BidiPendingFinish;
            rw_.Finish(final_status_, static_cast<CqTag*>(&finish_tag_));
        });
            state_ = State::BidiActive;
        } catch (const std::system_error& e) {
            // std::thread ctor failed (typically EAGAIN under RLIMIT_NPROC
            // or PID-cap squeeze). Reap the ServerCall via the unary
            // Finish path so the peer sees Internal rather than hanging
            // until deadline. spdlog before metric so operators correlate
            // (governance UP-1).
            spdlog::error(
                "yuzu::transport: bidi dispatcher std::thread ctor failed "
                "in {} — what={}",
                method_cache_, sanitise_status_detail(e.what()));
            if (listener_->opts_.metric_sink) {
                listener_->opts_.metric_sink->on_unexpected_dispatch_throw(
                    "grpc", method_cache_, "dispatcher_internal");
            }
            bidi_stream_.reset();  // not in use; release before Finish
            final_status_ = make_wire_status(
                StatusCode::Internal,
                "transport: bidi dispatcher unavailable");
            rw_.Finish(final_status_, static_cast<CqTag*>(this));
            state_ = State::UnaryPendingFinish;
        }
    }

    void dispatch_unary() {
        const std::string& method = gctx_.method();

        std::function<std::unique_ptr<SerializableMessage>()> req_factory;
        std::function<std::unique_ptr<SerializableMessage>()> resp_factory;
        UnaryHandler handler;
        {
            std::lock_guard<std::mutex> lock(listener_->mtx_);
            auto it = listener_->unary_handlers_.find(method);
            if (it == listener_->unary_handlers_.end()) {
                final_status_ = make_wire_status(
                    StatusCode::Unimplemented,
                    "transport: handler unregistered mid-call");
                rw_.Finish(final_status_, static_cast<CqTag*>(this));
                state_ = State::UnaryPendingFinish;
                return;
            }
            req_factory  = it->second.request_factory;
            resp_factory = it->second.response_factory;
            handler      = it->second.handler;
        }

        std::string req_bytes;
        if (!byte_buffer_to_string(req_buf_, req_bytes)) {
            final_status_ = make_wire_status(
                StatusCode::DataLoss,
                "transport: request ByteBuffer dump failed");
            rw_.Finish(final_status_, static_cast<CqTag*>(this));
            state_ = State::UnaryPendingFinish;
            return;
        }
        auto req_msg = req_factory();
        if (!req_msg || !req_msg->parse(req_bytes)) {
            final_status_ = make_wire_status(
                StatusCode::DataLoss, "transport: request parse failed");
            rw_.Finish(final_status_, static_cast<CqTag*>(this));
            state_ = State::UnaryPendingFinish;
            return;
        }

        CallContext ctx;
        ctx.peer_uri = gctx_.peer();

        auto resp_msg = resp_factory();
        if (!resp_msg) {
            final_status_ = make_wire_status(
                StatusCode::Internal,
                "transport: response factory returned null");
            rw_.Finish(final_status_, static_cast<CqTag*>(this));
            state_ = State::UnaryPendingFinish;
            return;
        }

        Status handler_status;
        try {
            handler_status = handler(ctx, *req_msg, *resp_msg);
        } catch (const std::exception& e) {
            handler_status = {StatusCode::Internal,
                              "handler raised exception"};
            spdlog::error(
                "yuzu::transport: handler raised std::exception in {} — "
                "type={} what={}", method, typeid(e).name(),
                sanitise_status_detail(e.what()));
            if (listener_->opts_.metric_sink) {
                listener_->opts_.metric_sink->on_unexpected_dispatch_throw(
                    "grpc", method, "std_exception");
            }
        } catch (...) {
            handler_status = {StatusCode::Internal,
                              "handler raised non-std exception"};
            spdlog::error(
                "yuzu::transport: handler raised non-std exception in {}",
                method);
            if (listener_->opts_.metric_sink) {
                listener_->opts_.metric_sink->on_unexpected_dispatch_throw(
                    "grpc", method, "non_std_exception");
            }
        }

        if (!handler_status.ok()) {
            final_status_ = to_grpc_status(handler_status);
            rw_.Finish(final_status_, static_cast<CqTag*>(this));
            state_ = State::UnaryPendingFinish;
            return;
        }

        std::string resp_bytes;
        if (!resp_msg->serialize(resp_bytes)) {
            final_status_ = make_wire_status(
                StatusCode::Internal, "transport: response serialize failed");
            rw_.Finish(final_status_, static_cast<CqTag*>(this));
            state_ = State::UnaryPendingFinish;
            return;
        }
        const std::size_t frame_cap =
            listener_->opts_.max_frame_size > 0
                ? listener_->opts_.max_frame_size
                : kDefaultMaxFrameSize;
        if (resp_bytes.size() > frame_cap) {
            final_status_ = make_wire_status(
                StatusCode::ResourceExhausted,
                "transport: response exceeds configured frame size");
            rw_.Finish(final_status_, static_cast<CqTag*>(this));
            state_ = State::UnaryPendingFinish;
            return;
        }

        resp_buf_     = string_to_byte_buffer(resp_bytes);
        final_status_ = ::grpc::Status::OK;
        rw_.WriteAndFinish(resp_buf_, ::grpc::WriteOptions(), final_status_,
                           static_cast<CqTag*>(this));
        state_ = State::UnaryPendingFinish;
    }

    State                                  state_     = State::PendingNew;
    GrpcServerListener*                    listener_  = nullptr;
    ::grpc::GenericServerContext           gctx_;
    ::grpc::GenericServerAsyncReaderWriter rw_;
    ::grpc::ByteBuffer                     req_buf_;
    ::grpc::ByteBuffer                     resp_buf_;
    // final_status_ MUST outlive the asynchronous Finish/WriteAndFinish
    // completion (governance F-CPP-3). The state machine guarantees
    // this: state_ = *PendingFinish is set immediately after issuing
    // Finish; `delete this` only fires in the matching PendingFinish
    // branch of on_event / on_bidi_finish.
    ::grpc::Status                         final_status_;

    // Bidi-mode state (unused on the unary path).
    ReadTag                                read_tag_;
    WriteTag                               write_tag_;
    FinishTag                              finish_tag_;
    std::thread                            handler_thread_;
    std::mutex                             bidi_mtx_;
    std::condition_variable                bidi_cv_;
    std::optional<bool>                    bidi_read_done_;
    std::optional<bool>                    bidi_write_done_;
    bool                                   bidi_cancelled_ = false;
    ::grpc::ByteBuffer                     bidi_read_buf_;
    ::grpc::ByteBuffer                     bidi_write_buf_;
    std::unique_ptr<ServerBidiStream>      bidi_stream_;
    std::string                            method_cache_;
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
        // pumping the CQ (governance UP-16). User handlers are caught
        // inside dispatch_unary / the bidi dispatcher thread; this outer
        // catch defends against bugs in the dispatcher itself, gRPC
        // interactions, or SerializableMessage adapters.
        try {
            static_cast<CqTag*>(tag)->on_event(ok);
        } catch (const std::exception& e) {
            spdlog::error(
                "yuzu::transport: dispatcher caught std::exception — "
                "type={} what={}", typeid(e).name(),
                sanitise_status_detail(e.what()));
            if (opts_.metric_sink) {
                opts_.metric_sink->on_unexpected_dispatch_throw(
                    "grpc", "", "dispatcher_internal");
            }
        } catch (...) {
            spdlog::error(
                "yuzu::transport: dispatcher caught non-std exception");
            if (opts_.metric_sink) {
                opts_.metric_sink->on_unexpected_dispatch_throw(
                    "grpc", "", "dispatcher_internal");
            }
        }
    }
}

void GrpcServerListener::wait_for_shutdown() {
    std::unique_lock<std::mutex> lock(mtx_);
    shutdown_cv_.wait(
        lock,
        [this] { return shutting_down_.load(std::memory_order_acquire); });
}

void GrpcServerListener::shutdown() {
    if (shutting_down_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    if (cq_worker_.joinable() &&
        cq_worker_.get_id() == std::this_thread::get_id()) {
        shutting_down_.store(false, std::memory_order_release);
        throw std::logic_error(
            "yuzu::transport: shutdown() must not be called from a handler "
            "running on the listener's CQ worker thread; arrange for an "
            "external thread to invoke shutdown() instead");
    }
    if (server_) {
        // PR 1b-3: bidi handlers in flight observe gRPC's UNAVAILABLE
        // delivery via peer-side cancel; the gctx_.IsCancelled signal
        // arrives as ok=false on outstanding Read/Write tags, so the
        // ServerBidiStream::read/write returns false and the handler
        // exits its loop. server_->Shutdown blocks until all Finish
        // tags drain.
        //
        // PR 1c may want a deadline-bounded form (governance UP-13) so
        // a stuck handler does not wedge shutdown indefinitely.
        server_->Shutdown();
    }
    if (cq_) {
        cq_->Shutdown();
    }
    if (cq_worker_.joinable()) {
        cq_worker_.join();
    }
    if (opts_.metric_sink) {
        opts_.metric_sink->on_connection_closed(
            "grpc", {StatusCode::Ok, "transport: listener shutdown"});
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
