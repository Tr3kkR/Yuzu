// SPDX-License-Identifier: Apache-2.0
// GrpcServerListener — the gRPC backend implementation of
// yuzu::transport::ServerListener.
//
// Internal header; consumers see only the abstract interface in
// <yuzu/transport/transport.hpp> and obtain instances via
// make_server_listener(Backend::Grpc).
//
// PR 1b-3 of #376 extends the AsyncGenericService dispatcher to handle
// bidi streams in addition to the unary path landed in PR 1b-2. The
// completion-queue tag-dispatch model now goes through a virtual
// CqTag interface so a single ServerCall can post multiple sub-tags
// (read/write/finish) without ambiguity.

#pragma once

#include <grpcpp/generic/async_generic_service.h>
#include <grpcpp/grpcpp.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <expected>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "yuzu/transport/transport.hpp"

namespace yuzu::transport::grpc_backend {

// Virtual interface implemented by anything posted as a CompletionQueue
// tag. The cq_worker loop static_casts the tag to CqTag* and calls
// on_event(ok); concrete callers (ServerCall, ServerCall sub-tags)
// route the event to their state machine.
//
// Each tag pointer MUST remain valid until the matching CQ event has
// been delivered; deletion happens in the terminal-state branch of the
// concrete on_event.
class CqTag {
public:
    virtual ~CqTag() = default;
    virtual void on_event(bool ok) = 0;
};

class ServerCall;  // implementation detail; defined in grpc_listener.cpp

class GrpcServerListener final : public ServerListener {
public:
    GrpcServerListener();
    ~GrpcServerListener() override;

    GrpcServerListener(const GrpcServerListener&)            = delete;
    GrpcServerListener& operator=(const GrpcServerListener&) = delete;

    void register_unary(
        std::string method,
        std::function<std::unique_ptr<SerializableMessage>()> request_factory,
        std::function<std::unique_ptr<SerializableMessage>()> response_factory,
        UnaryHandler handler) override;

    void register_bidi_stream(std::string method,
                              BidiStreamHandler handler) override;

    std::expected<void, Status> start(const Endpoint& bind,
                                      const Credentials& creds,
                                      const ListenerOptions& opts = {}) override;

    void wait_for_shutdown() override;
    void shutdown() override;
    bool is_serving() const noexcept override;
    Endpoint bound_endpoint() const noexcept override;

private:
    struct UnaryRegistration {
        std::function<std::unique_ptr<SerializableMessage>()> request_factory;
        std::function<std::unique_ptr<SerializableMessage>()> response_factory;
        UnaryHandler handler;
    };

    void enforce_method_or_die(const std::string& method);

    // ServerCall (defined in grpc_listener.cpp) drives the per-call state
    // machine and reads back through these accessors. Friend grants
    // access to unary_handlers_ / bidi_handlers_ for handler lookup,
    // and access to the bidi dispatcher pool members below.
    friend class ServerCall;
    void post_new_request_call();
    void cq_worker_loop();

    // Bidi dispatcher pool (governance UP-14, #904).
    // Pre-#904 the dispatcher spawned one std::thread per active bidi
    // RPC; at fleet scale this was unbounded (10K Subscribes ≈ 80 GiB
    // virtual address space on Linux defaults) and head-of-line-blocked
    // the cq_worker on handler_thread_.join() (UP-13). The pool is
    // sized at start(), pre-spawned, and reused across calls. New
    // submissions when the pool is saturated are rejected with
    // StatusCode::ResourceExhausted (operator-visible, fast-fail) rather
    // than queued unboundedly.
    void     bidi_pool_worker_loop();
    void     shutdown_bidi_pool();
    uint32_t resolve_bidi_pool_size(const ListenerOptions& opts) const noexcept;

    mutable std::mutex                       mtx_;
    std::condition_variable                  shutdown_cv_;
    std::map<std::string, UnaryRegistration> unary_handlers_;
    std::map<std::string, BidiStreamHandler> bidi_handlers_;
    ListenerOptions                          opts_;
    Endpoint                                 bound_endpoint_;  // populated post-BuildAndStart
    std::unique_ptr<::grpc::Server>          server_;
    ::grpc::AsyncGenericService              generic_service_;
    std::unique_ptr<::grpc::ServerCompletionQueue> cq_;
    std::thread                              cq_worker_;
    std::atomic<bool>                        started_{false};
    std::atomic<bool>                        shutting_down_{false};

    // Bidi pool state. bidi_in_flight_ is incremented under bidi_pool_mtx_
    // at submit time and decremented (with std::memory_order_release) by
    // the worker after run_bidi_handler returns. The cap-check at submit
    // is inside the same lock so it sees the latest value without races.
    uint32_t                                 bidi_pool_size_{0};
    std::atomic<uint32_t>                    bidi_in_flight_{0};
    std::mutex                               bidi_pool_mtx_;
    std::condition_variable                  bidi_pool_cv_;
    std::deque<ServerCall*>                  bidi_pool_queue_;
    std::vector<std::thread>                 bidi_pool_threads_;
    std::atomic<bool>                        bidi_pool_stop_{false};
};

}  // namespace yuzu::transport::grpc_backend
