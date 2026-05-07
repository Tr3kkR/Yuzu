// SPDX-License-Identifier: Apache-2.0
// GrpcChannel — the gRPC backend implementation of yuzu::transport::Channel.
//
// Internal header; consumers see only the abstract Channel interface
// in <yuzu/transport/transport.hpp> and obtain instances via
// make_channel(Backend::Grpc, ...).
//
// This file is part of PR 1 of #376. The full unary/bidi-stream
// dispatch is implemented in PR 1b atop grpc::GenericStub; PR 1a (this
// commit) covers construction, lifecycle, mTLS wiring, and stubs the
// RPC paths with StatusCode::Unimplemented placeholders so the lib
// builds and the abstraction can be smoke-tested.

#pragma once

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>

#include "yuzu/transport/transport.hpp"

namespace yuzu::transport::grpc_backend {

// Translate a yuzu::transport::Credentials block into a
// grpc::ChannelCredentials. mTLS material is consumed and (for the
// private key) zeroed via yuzu::secure_zero in the implementation.
std::shared_ptr<::grpc::ChannelCredentials> make_grpc_channel_credentials(
    const Credentials& creds, std::string& detail_out);

// Translate to grpc::ServerCredentials for the server side.
std::shared_ptr<::grpc::ServerCredentials> make_grpc_server_credentials(
    const Credentials& creds, std::string& detail_out);

class GrpcChannel final : public Channel {
public:
    // Sink-by-value: callers can std::move large Credentials/Endpoint
    // payloads in. Cheap structs (BackoffPolicy) are also by-value.
    GrpcChannel(Endpoint target, Credentials creds, BackoffPolicy backoff,
                std::shared_ptr<TransportMetricSink> metric_sink);
    ~GrpcChannel() override;

    GrpcChannel(const GrpcChannel&)            = delete;
    GrpcChannel& operator=(const GrpcChannel&) = delete;

    CallResult unary(std::string_view method, const CallContext& ctx,
                     const SerializableMessage& request,
                     SerializableMessage& response) override;

    std::unique_ptr<BidiStream> bidi_stream(std::string_view method,
                                            const CallContext& ctx) override;

    bool wait_for_connected(std::chrono::milliseconds deadline) override;

    void close() override;

private:
    Endpoint                                  target_;
    Credentials                               creds_;          // PEM private-key material zeroed in dtor
    BackoffPolicy                             backoff_;
    std::shared_ptr<TransportMetricSink>      metric_sink_;
    std::shared_ptr<::grpc::Channel>          channel_;        // null if construction failed
    std::atomic<bool>                         closed_{false};

    // Diagnostic detail captured during construction. If non-empty,
    // the channel is unusable and unary()/bidi_stream() return failure.
    std::string                               construction_error_;
};

}  // namespace yuzu::transport::grpc_backend
