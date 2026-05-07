// SPDX-License-Identifier: Apache-2.0

#include "grpc_channel.hpp"

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>

#include <chrono>
#include <regex>
#include <string>
#include <utility>

#include "yuzu/secure_zero.hpp"

namespace yuzu::transport::grpc_backend {

namespace {

// Method-name validator matching the proto contract — see
// proto/yuzu/transport/framing/v1/transport.proto, HandshakeHello.method.
// Anchored so partial matches are rejected.
bool method_name_well_formed(std::string_view method) {
    if (method.empty() || method.size() > kMaxMethodSize) return false;
    static const std::regex re{
        R"(^[A-Za-z][A-Za-z0-9_.]*\/[A-Za-z][A-Za-z0-9_]*$)"};
    return std::regex_match(method.begin(), method.end(), re);
}

}  // namespace

std::shared_ptr<::grpc::ChannelCredentials> make_grpc_channel_credentials(
    const Credentials& creds, std::string& detail_out) {
    if (creds.ca_cert_pem.empty() && creds.client_cert_pem.empty() &&
        creds.client_key_pem.empty()) {
        // Plaintext — only safe for tests.
        if (creds.verify_peer) {
            detail_out = "Credentials: plaintext mode requires verify_peer=false";
            return nullptr;
        }
        return ::grpc::InsecureChannelCredentials();
    }

    ::grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs    = creds.ca_cert_pem;
    ssl_opts.pem_cert_chain    = creds.client_cert_pem;
    ssl_opts.pem_private_key   = creds.client_key_pem;

    auto out = ::grpc::SslCredentials(ssl_opts);
    // Per Credentials zeroisation contract: PEM private key is zeroed
    // after consumption by the underlying TLS library. The local copy
    // in ssl_opts goes out of scope here; the caller owns the
    // Credentials struct and is expected to zero its own copy on
    // destruction.
    yuzu::secure_zero(ssl_opts.pem_private_key);
    return out;
}

std::shared_ptr<::grpc::ServerCredentials> make_grpc_server_credentials(
    const Credentials& creds, std::string& detail_out) {
    if (creds.server_cert_pem.empty() && creds.server_key_pem.empty() &&
        creds.ca_cert_pem.empty()) {
        if (creds.verify_peer ||
            creds.client_cert_mode == ClientCertMode::Require) {
            detail_out =
                "Credentials: plaintext mode requires verify_peer=false and "
                "client_cert_mode=None";
            return nullptr;
        }
        return ::grpc::InsecureServerCredentials();
    }

    ::grpc::SslServerCredentialsOptions::PemKeyCertPair kcp;
    kcp.private_key = creds.server_key_pem;
    kcp.cert_chain  = creds.server_cert_pem;

    ::grpc::SslServerCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = creds.ca_cert_pem;
    ssl_opts.pem_key_cert_pairs.push_back(kcp);
    switch (creds.client_cert_mode) {
        case ClientCertMode::None:
            ssl_opts.client_certificate_request =
                GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE;
            break;
        case ClientCertMode::Request:
            ssl_opts.client_certificate_request =
                creds.verify_peer
                    ? GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY
                    : GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_BUT_DONT_VERIFY;
            break;
        case ClientCertMode::Require:
            ssl_opts.client_certificate_request =
                GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
            break;
    }

    auto out = ::grpc::SslServerCredentials(ssl_opts);
    yuzu::secure_zero(kcp.private_key);
    return out;
}

GrpcChannel::GrpcChannel(const Endpoint& target, const Credentials& creds,
                         BackoffPolicy backoff,
                         std::shared_ptr<TransportMetricSink> metric_sink)
    : target_(target),
      creds_(creds),
      backoff_(backoff),
      metric_sink_(std::move(metric_sink)) {
    auto chan_creds = make_grpc_channel_credentials(creds_, construction_error_);
    if (!chan_creds) {
        // construction_error_ populated by the helper; channel_ stays null.
        return;
    }

    ::grpc::ChannelArguments args;
    // Apply BackoffPolicy to gRPC's reconnect backoff settings (these
    // names are gRPC-specific channel args).
    args.SetInt(GRPC_ARG_INITIAL_RECONNECT_BACKOFF_MS,
                static_cast<int>(backoff_.initial_delay.count()));
    args.SetInt(GRPC_ARG_MAX_RECONNECT_BACKOFF_MS,
                static_cast<int>(backoff_.max_delay.count()));
    args.SetInt(GRPC_ARG_MIN_RECONNECT_BACKOFF_MS,
                static_cast<int>(backoff_.initial_delay.count()));
    // PR 1b: jitter via custom reconnect logic — gRPC's built-in is
    // already jittered, but we should expose a knob to dampen it.

    // SNI override.
    if (!creds_.sni_hostname.empty()) {
        args.SetSslTargetNameOverride(creds_.sni_hostname);
    }

    const std::string addr = target_.host + ":" + std::to_string(target_.port);
    channel_ = ::grpc::CreateCustomChannel(addr, chan_creds, args);

    if (metric_sink_) metric_sink_->on_connection_opened("grpc");
}

GrpcChannel::~GrpcChannel() {
    close();
    yuzu::secure_zero(creds_.client_key_pem);
    yuzu::secure_zero(creds_.server_key_pem);
}

CallResult GrpcChannel::unary(std::string_view method,
                              const CallContext& /*ctx*/,
                              const SerializableMessage& /*request*/,
                              SerializableMessage& /*response*/) {
    CallResult r;
    if (!construction_error_.empty()) {
        r.status = {StatusCode::Unauthenticated, construction_error_};
        return r;
    }
    if (closed_.load(std::memory_order_acquire)) {
        r.status = {StatusCode::Cancelled, "channel closed"};
        return r;
    }
    if (!method_name_well_formed(method)) {
        r.status = {StatusCode::InvalidArgument,
                    "method name fails validation contract"};
        return r;
    }
    // PR 1b: dispatch through grpc::GenericStub. PR 1a returns
    // Unimplemented so callers receive a deterministic placeholder
    // and the surface compiles.
    r.status = {StatusCode::Unimplemented,
                "grpc_transport unary RPC dispatch lands in PR 1b"};
    return r;
}

std::unique_ptr<BidiStream> GrpcChannel::bidi_stream(std::string_view /*method*/,
                                                     const CallContext& /*ctx*/) {
    // PR 1b: bidi via grpc::GenericStub::PrepareBidiStreamingCall.
    // Returning nullptr in PR 1a is the deterministic placeholder
    // (callers check for null before use).
    return nullptr;
}

bool GrpcChannel::wait_for_connected(std::chrono::milliseconds deadline) {
    if (!channel_) return false;
    const auto when = std::chrono::system_clock::now() + deadline;
    // GRPC_CHANNEL_READY is the "transport-level handshake complete,
    // ready to accept new streams" state per the abstraction's
    // wait_for_connected contract.
    return channel_->WaitForConnected(when);
}

void GrpcChannel::close() {
    if (closed_.exchange(true, std::memory_order_acq_rel)) {
        return;  // idempotent
    }
    if (metric_sink_) {
        metric_sink_->on_connection_closed("grpc",
                                           {StatusCode::Ok, "channel closed"});
    }
    // grpc::Channel has no explicit close; dropping the shared_ptr is
    // sufficient. Active calls observe transient FAILURE on next op.
    channel_.reset();
}

}  // namespace yuzu::transport::grpc_backend
