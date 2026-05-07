// SPDX-License-Identifier: Apache-2.0
// GrpcServerListener — the gRPC backend implementation of
// yuzu::transport::ServerListener.
//
// Internal header; consumers see only the abstract interface in
// <yuzu/transport/transport.hpp> and obtain instances via
// make_server_listener(Backend::Grpc).
//
// This file is part of PR 1 of #376. PR 1a (this commit) covers
// lifecycle (start/shutdown/wait_for_shutdown/is_serving) and handler
// registration; the actual generic-dispatch wiring atop
// grpc::AsyncGenericService lands in PR 1b.

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

private:
    struct UnaryRegistration {
        std::function<std::unique_ptr<SerializableMessage>()> request_factory;
        std::function<std::unique_ptr<SerializableMessage>()> response_factory;
        UnaryHandler handler;
    };

    void enforce_method_or_die(const std::string& method);

    // ServerCall (defined in grpc_listener.cpp) drives the per-call state
    // machine and reads back through these accessors. Friend grants
    // access to unary_handlers_ for handler lookup.
    friend class ServerCall;
    void post_new_request_call();
    void cq_worker_loop();

    mutable std::mutex                       mtx_;
    std::condition_variable                  shutdown_cv_;
    std::map<std::string, UnaryRegistration> unary_handlers_;
    std::map<std::string, BidiStreamHandler> bidi_handlers_;
    ListenerOptions                          opts_;
    std::unique_ptr<::grpc::Server>          server_;
    ::grpc::AsyncGenericService              generic_service_;
    std::unique_ptr<::grpc::ServerCompletionQueue> cq_;
    std::thread                              cq_worker_;
    std::atomic<bool>                        started_{false};
    std::atomic<bool>                        shutting_down_{false};
};

}  // namespace yuzu::transport::grpc_backend
