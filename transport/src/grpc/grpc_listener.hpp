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
#include <expected>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

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
    // access to unary_handlers_ / bidi_handlers_ for handler lookup.
    friend class ServerCall;
    void post_new_request_call();
    void cq_worker_loop();

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
};

}  // namespace yuzu::transport::grpc_backend
