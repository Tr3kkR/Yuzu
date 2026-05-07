// SPDX-License-Identifier: Apache-2.0

#include "grpc_channel.hpp"

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>

#include "grpc_method_validator.hpp"  // method_name_well_formed
#include "yuzu/secure_zero.hpp"

namespace yuzu::transport::grpc_backend {

namespace {

// Clamp a milliseconds value into the int range that grpc channel args
// require, while preserving sign + ordering. Avoids the silent
// truncation that would let a 49-day max_delay wrap to a negative int
// and produce an erratic reconnect curve. (governance UP-4)
int clamp_ms_to_int(std::chrono::milliseconds ms) noexcept {
    using rep = std::chrono::milliseconds::rep;
    constexpr auto kIntMax = static_cast<rep>(std::numeric_limits<int>::max());
    constexpr auto kIntMin = static_cast<rep>(std::numeric_limits<int>::min());
    return static_cast<int>(std::clamp<rep>(ms.count(), kIntMin, kIntMax));
}

}  // namespace

std::shared_ptr<::grpc::ChannelCredentials> make_grpc_channel_credentials(
    const Credentials& creds, std::string& detail_out) {
    if (creds.ca_cert_pem.empty() && creds.client_cert_pem.empty() &&
        creds.client_key_pem.empty()) {
        // Plaintext — only safe for tests.
        if (creds.verify_peer) {
            detail_out =
                "Credentials: plaintext mode requires verify_peer=false";
            return nullptr;
        }
        return ::grpc::InsecureChannelCredentials();
    }

    // Asymmetric mTLS material (cert without key, or vice versa) is a
    // silent foot-gun: gRPC accepts the construction but every TLS
    // handshake fails, with no signal at the C++ level. Reject pre-flight
    // so construction_error_ on the channel surfaces the bug. (governance
    // UP-1)
    if (creds.client_cert_pem.empty() != creds.client_key_pem.empty()) {
        detail_out =
            "Credentials: client_cert_pem and client_key_pem must both be set "
            "or both empty";
        return nullptr;
    }

    ::grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs  = creds.ca_cert_pem;
    ssl_opts.pem_cert_chain  = creds.client_cert_pem;
    ssl_opts.pem_private_key = creds.client_key_pem;

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

    // Asymmetric server-side mTLS material — same hazard as client side.
    // (governance UP-1)
    if (creds.server_cert_pem.empty() != creds.server_key_pem.empty()) {
        detail_out =
            "Credentials: server_cert_pem and server_key_pem must both be set "
            "or both empty";
        return nullptr;
    }

    ::grpc::SslServerCredentialsOptions::PemKeyCertPair kcp;
    kcp.private_key = creds.server_key_pem;
    kcp.cert_chain  = creds.server_cert_pem;

    ::grpc::SslServerCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = creds.ca_cert_pem;
    ssl_opts.pem_key_cert_pairs.push_back(std::move(kcp));
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
    // Zero the live copy that ssl_opts.pem_key_cert_pairs holds, not just
    // the local kcp (which was moved-from above and contains an empty
    // string). Sibling parity with server/core/src/server.cpp:1213-1216.
    // (governance cons-S2)
    for (auto& pair : ssl_opts.pem_key_cert_pairs) {
        yuzu::secure_zero(pair.private_key);
    }
    return out;
}

GrpcChannel::GrpcChannel(Endpoint target, Credentials creds,
                         BackoffPolicy backoff,
                         std::shared_ptr<TransportMetricSink> metric_sink)
    : target_(std::move(target)),
      creds_(std::move(creds)),
      backoff_(std::move(backoff)),
      metric_sink_(std::move(metric_sink)) {
    auto chan_creds =
        make_grpc_channel_credentials(creds_, construction_error_);
    if (!chan_creds) {
        // construction_error_ populated by the helper; channel_ stays null.
        return;
    }

    // BackoffPolicy invariant: initial_delay <= max_delay. A misconfigured
    // policy that violates this would produce implementation-defined
    // gRPC reconnect behaviour; reject and surface via construction_error_.
    // (governance UP-5)
    if (backoff_.initial_delay > backoff_.max_delay) {
        construction_error_ =
            "BackoffPolicy: initial_delay must be <= max_delay";
        return;
    }

    ::grpc::ChannelArguments args;
    // Apply BackoffPolicy to gRPC's reconnect backoff settings (these
    // names are gRPC-specific channel args). Clamp to int range to avoid
    // silent truncation/wrapping for very long durations. (UP-4)
    args.SetInt(GRPC_ARG_INITIAL_RECONNECT_BACKOFF_MS,
                clamp_ms_to_int(backoff_.initial_delay));
    args.SetInt(GRPC_ARG_MAX_RECONNECT_BACKOFF_MS,
                clamp_ms_to_int(backoff_.max_delay));
    args.SetInt(GRPC_ARG_MIN_RECONNECT_BACKOFF_MS,
                clamp_ms_to_int(backoff_.initial_delay));
    // PR 1b: surface a jitter knob; gRPC's built-in is already jittered.

    // SNI override is only meaningful on TLS channels — applying it to a
    // plaintext channel is implementation-defined and masks a config bug.
    // (governance UP-3)
    if (!creds_.sni_hostname.empty()) {
        const bool is_tls = !creds_.ca_cert_pem.empty() ||
                            !creds_.client_cert_pem.empty() ||
                            !creds_.client_key_pem.empty();
        if (!is_tls) {
            construction_error_ =
                "Credentials: sni_hostname is only valid with TLS material";
            return;
        }
        args.SetSslTargetNameOverride(creds_.sni_hostname);
    }

    const std::string addr =
        target_.host + ":" + std::to_string(target_.port);
    channel_ = ::grpc::CreateCustomChannel(addr, chan_creds, args);

    if (metric_sink_) metric_sink_->on_connection_opened("grpc");
}

GrpcChannel::~GrpcChannel() {
    // close() invokes the user-supplied metric_sink_ callback. A throwing
    // sink would call std::terminate from this dtor BEFORE secure_zero
    // runs, leaving PEM key material resident in heap. Swallow any
    // throw so the zeroisation contract holds. (governance UP-10)
    try {
        close();
    } catch (...) {
        // Metric sinks are documented as noexcept; swallow defensively.
    }
    // creds_.server_key_pem is structurally always empty on the client
    // side, but zeroing both is cheap and defensive (governance nice-3
    // demoted from "dead code" to "defence-in-depth comment"). The
    // public PEMs (ca/cert) are not secrets; only the private key is.
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

std::unique_ptr<BidiStream> GrpcChannel::bidi_stream(
    std::string_view /*method*/, const CallContext& /*ctx*/) {
    // PR 1b: bidi via grpc::GenericStub::PrepareBidiStreamingCall.
    // Returning nullptr in PR 1a is the deterministic placeholder
    // (callers MUST check for null before use; PR 1b will also need
    // the construction_error_ + closed_ + method-validation gates that
    // unary() currently has — tracked as governance UP-8).
    return nullptr;
}

bool GrpcChannel::wait_for_connected(std::chrono::milliseconds deadline) {
    if (!channel_) return false;
    // gRPC's TimePoint adapter explicitly deletes overloads for
    // non-system_clock time_points (grpcpp/support/time.h:46-47), so
    // wall-clock is the only available option here. NTP-step risk is
    // bounded by the typical short wait deadline; revisit when gRPC
    // exposes a steady-clock-friendly waitable.
    const auto when = std::chrono::system_clock::now() + deadline;
    return channel_->WaitForConnected(when);
}

void GrpcChannel::close() {
    if (closed_.exchange(true, std::memory_order_acq_rel)) {
        return;  // idempotent
    }
    if (metric_sink_) {
        metric_sink_->on_connection_closed(
            "grpc", {StatusCode::Ok, "channel closed"});
    }
    // grpc::Channel has no explicit close; dropping the shared_ptr is
    // sufficient. Active calls observe transient FAILURE on next op.
    channel_.reset();
}

}  // namespace yuzu::transport::grpc_backend
