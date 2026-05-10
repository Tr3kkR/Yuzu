// SPDX-License-Identifier: Apache-2.0

#include "grpc_listener.hpp"

#include <grpcpp/generic/async_generic_service.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/support/byte_buffer.h>
#include <grpcpp/support/slice.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <deque>
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

// Populate `ctx.peer_uri`, `ctx.peer_san_identities`, and `ctx.metadata`
// from the per-call grpc::ServerContext. Server-handler ergonomics
// (PR 1c-2): without these fields, lifted handlers would still need a
// grpc::ServerContext* to resolve their caller, which defeats the
// abstraction. Bounded by the metadata limits in transport.hpp so a
// misbehaving client cannot flood per-call state.
void populate_call_context_from_grpc(CallContext& ctx,
                                     const ::grpc::ServerContext& gctx) {
    ctx.peer_uri = gctx.peer();

    if (auto auth_ctx = gctx.auth_context();
        auth_ctx && auth_ctx->IsPeerAuthenticated()) {
        // Mirror AgentServiceImpl::extract_peer_identities (the historic
        // pre-#376 source of truth for peer-identity authn): union of
        // GetPeerIdentity() + CN + SAN, deduplicated, in stable order.
        // Despite the abstraction's field being named `peer_san_identities`,
        // it is the canonical "verified peer identities for authn"
        // surface — the gRPC backend folds CN + GetPeerIdentity in so
        // mTLS-CN-issued client certs (still common in the field) keep
        // working after the lift. The msquic backend will make its own
        // call but MUST satisfy the same authn contract.
        auto append_unique = [&](std::string_view sv) {
            if (sv.empty()) return;
            if (ctx.peer_san_identities.size() >= kMaxMetadataEntries) return;
            for (const auto& existing : ctx.peer_san_identities) {
                if (existing == sv) return;
            }
            ctx.peer_san_identities.emplace_back(sv);
        };
        for (const auto& id : auth_ctx->GetPeerIdentity()) {
            append_unique({id.data(), id.size()});
        }
        for (const auto& cn :
             auth_ctx->FindPropertyValues("x509_common_name")) {
            append_unique({cn.data(), cn.size()});
        }
        for (const auto& sv :
             auth_ctx->FindPropertyValues("x509_subject_alternative_name")) {
            append_unique({sv.data(), sv.size()});
        }
    }

    const auto& md = gctx.client_metadata();
    for (const auto& kv : md) {
        if (ctx.metadata.size() >= kMaxMetadataEntries) break;
        if (kv.first.size() > kMaxMetadataKeySize) continue;
        if (kv.second.size() > kMaxMetadataValueSize) continue;
        // gRPC's client_metadata() is a std::multimap — duplicate keys
        // can carry distinct values. CallContext::metadata is a std::map.
        // Pre-#376 callers used `multimap::find(key)` which returns the
        // FIRST inserted occurrence; we must preserve that selection
        // rule across the lift (gov round 7 sec LOW). Use try_emplace so
        // a second occurrence of the same key is dropped, not allowed
        // to overwrite. Counter accuracy (cpp F-CPP-6) flows from
        // checking `metadata.size()` instead of a separate `kept`
        // counter that double-counted skipped duplicates against the
        // cap.
        ctx.metadata.try_emplace(std::string(kv.first.data(), kv.first.size()),
                                 std::string(kv.second.data(), kv.second.size()));
    }
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
        // Terminal for the bidi path. The pool worker that ran
        // run_bidi_handler has already returned to the dispatcher
        // pool; nothing per-call to join. Self-delete.
        //
        // Pre-#904 (governance UP-14) this used to handler_thread_.join()
        // a per-call std::thread, which head-of-line-blocked the
        // cq_worker (UP-13) when a handler was slow to exit. The bounded
        // dispatcher pool moved that concern to ListenerOptions::
        // bidi_dispatcher_pool_size — operators bound the total thread
        // count and the cq_worker no longer joins per-call threads.
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

        bool write(const SerializableMessage& msg,
                   std::chrono::milliseconds deadline =
                       std::chrono::milliseconds::zero()) override {
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
            const auto pred = [this] {
                return call_->bidi_write_done_.has_value() ||
                       call_->bidi_cancelled_;
            };
            // Negative deadline → treated as zero (unbounded). Symmetric
            // with the read-side semantics; the `> zero()` check below
            // routes negatives to the unbounded `else` branch
            // (#915 / UP-110).
            if (deadline > std::chrono::milliseconds::zero()) {
                // Per-frame write deadline (#911 / UP-101). On expiry:
                // mark deadline-exceeded for final_status() reporting,
                // flip bidi_cancelled_, then TryCancel so the cq_worker
                // delivers the write_tag completion (with ok=false) and
                // the dispatcher proceeds to Finish. Mirrors the
                // read-side pattern.
                if (!call_->bidi_cv_.wait_for(lock, deadline, pred)) {
                    call_->bidi_write_deadline_exceeded_ = true;
                    call_->bidi_cancelled_               = true;
                    call_->bidi_cv_.notify_all();
                    call_->gctx_.TryCancel();
                    return false;
                }
            } else {
                call_->bidi_cv_.wait(lock, pred);
            }
            if (call_->bidi_cancelled_) return false;
            const bool ok = *call_->bidi_write_done_;
            if (ok && call_->listener_->opts_.metric_sink) {
                call_->listener_->opts_.metric_sink->on_bytes_sent(
                    "grpc", bytes.size());
            }
            return ok;
        }

        bool read(SerializableMessage& msg,
                  std::chrono::milliseconds deadline =
                      std::chrono::milliseconds::zero()) override {
            std::unique_lock<std::mutex> lock(call_->bidi_mtx_);
            if (call_->bidi_cancelled_) return false;
            call_->bidi_read_done_.reset();
            call_->bidi_read_buf_.Clear();
            call_->rw_.Read(&call_->bidi_read_buf_,
                            static_cast<CqTag*>(&call_->read_tag_));
            const auto pred = [this] {
                return call_->bidi_read_done_.has_value() ||
                       call_->bidi_cancelled_;
            };
            // Negative deadline → treated as zero (unbounded). See the
            // BidiStream contract block in transport.hpp. The `> zero()`
            // check below routes negatives to the `else` branch, which
            // is the unbounded wait — defensive against callers using
            // `deadline = target - now()` patterns where the underflow
            // would otherwise pin the stream forever (#915 / UP-110).
            if (deadline > std::chrono::milliseconds::zero()) {
                // Idle-read timeout (#902 / UP-8). On expiry: mark
                // deadline-exceeded for final_status() reporting, flip
                // bidi_cancelled_ to short-circuit subsequent
                // reads/writes, then TryCancel so the cq_worker
                // eventually delivers the read_tag completion (with
                // ok=false) and the dispatcher proceeds to Finish.
                // Lock order: bidi_mtx_ is held across TryCancel; gctx_
                // is owned by this ServerCall and TryCancel is
                // documented thread-safe by gRPC.
                if (!call_->bidi_cv_.wait_for(lock, deadline, pred)) {
                    call_->bidi_read_deadline_exceeded_ = true;
                    call_->bidi_cancelled_ = true;
                    call_->bidi_cv_.notify_all();
                    call_->gctx_.TryCancel();
                    return false;
                }
            } else {
                call_->bidi_cv_.wait(lock, pred);
            }
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
            // with the BidiStream contract — UNLESS read() OR write()
            // observed a deadline expiry (#902 / UP-8 / #911 / UP-101),
            // in which case the contract block in transport.hpp requires
            // DeadlineExceeded so the handler can distinguish it from
            // peer half-close / external cancel().
            std::lock_guard<std::mutex> lock(call_->bidi_mtx_);
            if (call_->bidi_read_deadline_exceeded_) {
                return Status{StatusCode::DeadlineExceeded,
                              "transport: bidi read deadline exceeded"};
            }
            if (call_->bidi_write_deadline_exceeded_) {
                return Status{StatusCode::DeadlineExceeded,
                              "transport: bidi write deadline exceeded"};
            }
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

        method_cache_ = method;  // copy out; gctx_ stays valid for lifetime

        // Submit to the bounded dispatcher pool (governance UP-14, #904).
        //
        // Lifetime invariant (governance UP-1): state_ MUST stay
        // PendingNew until the call has been committed to the pool's
        // queue. If a throw escapes the submit path BEFORE we set
        // state_ = BidiActive, this ServerCall must reach the
        // UnaryPendingFinish reaper via the explicit fall-through below
        // — otherwise the cq_worker has no tag to deliver and the call
        // leaks (peer hangs until deadline). The two-step catch matches
        // the round-6 broadened pattern (std::bad_alloc may escape
        // make_unique<ServerBidiStream> or deque::push_back; we MUST NOT
        // let it unwind through the cq_worker).
        bool enqueued = false;
        try {
            bidi_stream_ = std::make_unique<ServerBidiStream>(this);
            handler_     = std::move(handler);

            std::unique_lock<std::mutex> pool_lock(listener_->bidi_pool_mtx_);
            const uint32_t cap = listener_->bidi_pool_size_;
            const uint32_t in_flight =
                listener_->bidi_in_flight_.load(std::memory_order_acquire);
            if (!listener_->bidi_pool_stop_.load(std::memory_order_acquire) &&
                cap > 0 && in_flight < cap) {
                listener_->bidi_pool_queue_.push_back(this);
                listener_->bidi_in_flight_.fetch_add(
                    1, std::memory_order_release);
                state_   = State::BidiActive;
                enqueued = true;
            }
        } catch (const std::exception& e) {
            spdlog::error(
                "yuzu::transport: bidi dispatcher submit failed in "
                "{} — type={} what={}",
                method_cache_, typeid(e).name(),
                sanitise_status_detail(e.what()));
            if (listener_->opts_.metric_sink) {
                listener_->opts_.metric_sink->on_unexpected_dispatch_throw(
                    "grpc", method_cache_, "dispatcher_internal");
            }
            bidi_stream_.reset();
            handler_ = nullptr;
            final_status_ = make_wire_status(
                StatusCode::Internal,
                "transport: bidi dispatcher unavailable");
            rw_.Finish(final_status_, static_cast<CqTag*>(this));
            state_ = State::UnaryPendingFinish;
            return;
        } catch (...) {
            spdlog::error(
                "yuzu::transport: bidi dispatcher submit failed in {} "
                "(non-std exception)",
                method_cache_);
            if (listener_->opts_.metric_sink) {
                listener_->opts_.metric_sink->on_unexpected_dispatch_throw(
                    "grpc", method_cache_, "dispatcher_internal");
            }
            bidi_stream_.reset();
            handler_ = nullptr;
            final_status_ = make_wire_status(
                StatusCode::Internal,
                "transport: bidi dispatcher unavailable");
            rw_.Finish(final_status_, static_cast<CqTag*>(this));
            state_ = State::UnaryPendingFinish;
            return;
        }

        if (enqueued) {
            // Wake at most one idle worker. The pool is bounded so the
            // queue never holds more than `cap` calls concurrently.
            listener_->bidi_pool_cv_.notify_one();
            return;
        }

        // Pool saturated (or shutting down). Reject fast — peer sees
        // ResourceExhausted immediately rather than waiting for a thread
        // to free up. Operator can scale ListenerOptions::
        // bidi_dispatcher_pool_size or front the listener with the
        // gateway (which terminates Subscribe per-fleet).
        bidi_stream_.reset();
        handler_ = nullptr;
        if (listener_->opts_.metric_sink) {
            listener_->opts_.metric_sink->on_unexpected_dispatch_throw(
                "grpc", method_cache_, "dispatcher_internal");
        }
        final_status_ = make_wire_status(
            StatusCode::ResourceExhausted,
            "transport: bidi dispatcher saturated");
        rw_.Finish(final_status_, static_cast<CqTag*>(this));
        state_ = State::UnaryPendingFinish;
    }

public:
    // Invoked by a GrpcServerListener pool worker after popping this
    // ServerCall off bidi_pool_queue_. Public so the pool worker can
    // reach it from outside the class; private would require a friend
    // declaration on the listener which is broader access. Runs the
    // user handler with the bidi surface, then schedules Finish on the
    // cq_worker. Lifetime: the ServerCall remains alive until
    // on_bidi_finish reaps it (which fires when the wire Finish
    // completes). The pool worker holds no per-call ownership after
    // this method returns; bidi_in_flight_ decrement happens in the
    // worker loop.
    void run_bidi_handler() {
        CallContext ctx;
        populate_call_context_from_grpc(ctx, gctx_);

        Status handler_status;
        try {
            handler_status = handler_(ctx, *bidi_stream_);
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
        // events arrive on the bidi sub-tags except finish_tag_. The
        // pool worker returns to the queue; the cq_worker's
        // on_bidi_finish self-deletes this ServerCall.
        final_status_ = to_grpc_status(handler_status);
        state_        = State::BidiPendingFinish;
        rw_.Finish(final_status_, static_cast<CqTag*>(&finish_tag_));
    }

private:
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
        populate_call_context_from_grpc(ctx, gctx_);

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
    BidiStreamHandler                      handler_;       // bound at dispatch_bidi, run by pool worker
    std::mutex                             bidi_mtx_;
    std::condition_variable                bidi_cv_;
    std::optional<bool>                    bidi_read_done_;
    std::optional<bool>                    bidi_write_done_;
    bool                                   bidi_cancelled_ = false;
    // Set by ServerBidiStream::read when its idle-read deadline lapses
    // before a frame arrives (#902 / UP-8). Distinguishes deadline
    // cancellation from peer half-close / external cancel() so that
    // ServerBidiStream::final_status() can report DeadlineExceeded —
    // matches BidiStream contract block.
    bool                                   bidi_read_deadline_exceeded_ = false;
    // Set by ServerBidiStream::write when its per-frame write deadline
    // lapses before the transport accepts the frame (#911 / UP-101).
    // Same final_status() promotion semantics as bidi_read_deadline_exceeded_.
    bool                                   bidi_write_deadline_exceeded_ = false;
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

    // Pool resolution + pre-spawn happens BEFORE we accept the first
    // RPC (post_new_request_call below). If the pool fails to come up
    // we tear down server_/cq_ synchronously so start() reports failure
    // atomically — partial-listener state is never observable.
    bidi_pool_size_ = resolve_bidi_pool_size(opts);
    bidi_in_flight_.store(0, std::memory_order_release);
    bidi_pool_stop_.store(false, std::memory_order_release);
    try {
        bidi_pool_threads_.reserve(bidi_pool_size_);
        for (uint32_t i = 0; i < bidi_pool_size_; ++i) {
            bidi_pool_threads_.emplace_back([this] { bidi_pool_worker_loop(); });
        }
    } catch (...) {
        // Roll back: stop+join any successfully-started workers and
        // tear down the server_/cq_ we already built so the caller sees
        // a clean failed start, not a half-running listener.
        bidi_pool_stop_.store(true, std::memory_order_release);
        bidi_pool_cv_.notify_all();
        for (auto& w : bidi_pool_threads_) {
            if (w.joinable()) w.join();
        }
        bidi_pool_threads_.clear();
        bidi_pool_size_ = 0;
        if (server_) {
            server_->Shutdown();
            server_.reset();
        }
        cq_.reset();
        started_.store(false, std::memory_order_release);
        return std::unexpected(Status{
            StatusCode::ResourceExhausted,
            "transport: bidi dispatcher pool construction failed"});
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

    // Pool drain (governance UP-14, #904). At this point: server_ has
    // drained outstanding Finish tags (so all in-flight bidi handlers
    // have posted Finish and returned to the pool); cq_worker has
    // exited (no new dispatches); workers are idle on bidi_pool_cv_.
    // shutdown_bidi_pool sets the stop flag, wakes them, and joins.
    // Pool MUST drain after cq_worker exits — handlers that blocked on
    // bidi_cv_ depend on cq_worker delivering events; killing the pool
    // before cq_worker finishes would risk hanging a handler waiting
    // on a never-arriving event.
    shutdown_bidi_pool();

    if (opts_.metric_sink) {
        opts_.metric_sink->on_connection_closed(
            "grpc", {StatusCode::Ok, "transport: listener shutdown"});
    }
    {
        std::lock_guard<std::mutex> lock(mtx_);
        shutdown_cv_.notify_all();
    }
}

uint32_t GrpcServerListener::resolve_bidi_pool_size(
    const ListenerOptions& opts) const noexcept {
    if (opts.bidi_dispatcher_pool_size > 0) {
        return opts.bidi_dispatcher_pool_size;
    }
    // Auto-compute. hardware_concurrency() can return 0 on some
    // freestanding/containerised systems; treat 0 as 4 so the formula
    // still produces a sensible default.
    unsigned hw = std::thread::hardware_concurrency();
    if (hw == 0) hw = 4;
    uint64_t computed = static_cast<uint64_t>(hw) * 8;
    if (computed < 64) computed   = 64;
    if (computed > 4096) computed = 4096;
    return static_cast<uint32_t>(computed);
}

void GrpcServerListener::bidi_pool_worker_loop() {
    while (true) {
        ServerCall* call = nullptr;
        {
            std::unique_lock<std::mutex> lock(bidi_pool_mtx_);
            bidi_pool_cv_.wait(lock, [this] {
                return bidi_pool_stop_.load(std::memory_order_acquire) ||
                       !bidi_pool_queue_.empty();
            });
            // Stop flag is checked first: if shutdown raced with a
            // submission, the submitter would have observed
            // bidi_pool_stop_ and rejected. We MUST NOT pop a queued
            // call after stop because cq_worker may already have
            // exited — handler I/O ops would hang on bidi_cv_ with no
            // one to deliver events.
            if (bidi_pool_stop_.load(std::memory_order_acquire)) {
                return;
            }
            call = bidi_pool_queue_.front();
            bidi_pool_queue_.pop_front();
        }
        try {
            call->run_bidi_handler();
        } catch (const std::exception& e) {
            // run_bidi_handler catches handler-thrown exceptions
            // already; this outer catch defends against a throw in the
            // dispatcher itself (e.g. CallContext population, status
            // translation). Mirror cq_worker_loop's defence: log,
            // emit dispatch_throw metric, do NOT propagate (would
            // unwind the worker thread and shrink the pool below
            // bidi_pool_size_).
            spdlog::error(
                "yuzu::transport: bidi pool worker caught std::exception — "
                "type={} what={}", typeid(e).name(),
                sanitise_status_detail(e.what()));
            if (opts_.metric_sink) {
                opts_.metric_sink->on_unexpected_dispatch_throw(
                    "grpc", "", "dispatcher_internal");
            }
        } catch (...) {
            spdlog::error(
                "yuzu::transport: bidi pool worker caught non-std exception");
            if (opts_.metric_sink) {
                opts_.metric_sink->on_unexpected_dispatch_throw(
                    "grpc", "", "dispatcher_internal");
            }
        }
        bidi_in_flight_.fetch_sub(1, std::memory_order_release);
    }
}

void GrpcServerListener::shutdown_bidi_pool() {
    {
        std::lock_guard<std::mutex> lock(bidi_pool_mtx_);
        bidi_pool_stop_.store(true, std::memory_order_release);
    }
    bidi_pool_cv_.notify_all();
    for (auto& w : bidi_pool_threads_) {
        if (w.joinable()) w.join();
    }
    bidi_pool_threads_.clear();

    // After all workers exited, the queue MUST be empty (cq_worker
    // exited before this is called, so no new dispatch_bidi can run;
    // existing in-flight handlers had already posted Finish and the
    // worker decremented bidi_in_flight_). Defensive drain in case
    // the listener was torn down without start ever accepting a call,
    // or a future code path enqueues during shutdown.
    while (!bidi_pool_queue_.empty()) {
        delete bidi_pool_queue_.front();
        bidi_pool_queue_.pop_front();
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
