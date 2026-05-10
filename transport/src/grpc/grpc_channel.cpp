// SPDX-License-Identifier: Apache-2.0

#include "grpc_channel.hpp"

#include <grpcpp/generic/generic_stub.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/support/byte_buffer.h>
#include <grpcpp/support/slice.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <spdlog/spdlog.h>

#include "grpc_internal_helpers.hpp"  // method_name_well_formed, byte helpers, sanitise
#include "transport.pb.h"             // proto StatusCode enum for static_assert
#include "yuzu/secure_zero.hpp"

// Wire-stability assertion. Per the FROZEN commitment in
// transport.proto and transport.hpp, the C++ enum class StatusCode and
// the generated proto enum yuzu::transport::framing::v1::StatusCode
// share numeric values. Drift here = silent error-mapping break.
namespace {
namespace pb = ::yuzu::transport::framing::v1;
namespace yt = ::yuzu::transport;
static_assert(static_cast<int>(yt::StatusCode::Ok) == pb::STATUS_CODE_OK);
static_assert(static_cast<int>(yt::StatusCode::Cancelled) == pb::STATUS_CODE_CANCELLED);
static_assert(static_cast<int>(yt::StatusCode::Unknown) == pb::STATUS_CODE_UNKNOWN);
static_assert(static_cast<int>(yt::StatusCode::InvalidArgument) == pb::STATUS_CODE_INVALID_ARGUMENT);
static_assert(static_cast<int>(yt::StatusCode::DeadlineExceeded) == pb::STATUS_CODE_DEADLINE_EXCEEDED);
static_assert(static_cast<int>(yt::StatusCode::NotFound) == pb::STATUS_CODE_NOT_FOUND);
static_assert(static_cast<int>(yt::StatusCode::AlreadyExists) == pb::STATUS_CODE_ALREADY_EXISTS);
static_assert(static_cast<int>(yt::StatusCode::PermissionDenied) == pb::STATUS_CODE_PERMISSION_DENIED);
static_assert(static_cast<int>(yt::StatusCode::ResourceExhausted) == pb::STATUS_CODE_RESOURCE_EXHAUSTED);
static_assert(static_cast<int>(yt::StatusCode::FailedPrecondition) == pb::STATUS_CODE_FAILED_PRECONDITION);
static_assert(static_cast<int>(yt::StatusCode::Aborted) == pb::STATUS_CODE_ABORTED);
static_assert(static_cast<int>(yt::StatusCode::OutOfRange) == pb::STATUS_CODE_OUT_OF_RANGE);
static_assert(static_cast<int>(yt::StatusCode::Unimplemented) == pb::STATUS_CODE_UNIMPLEMENTED);
static_assert(static_cast<int>(yt::StatusCode::Internal) == pb::STATUS_CODE_INTERNAL);
static_assert(static_cast<int>(yt::StatusCode::Unavailable) == pb::STATUS_CODE_UNAVAILABLE);
static_assert(static_cast<int>(yt::StatusCode::DataLoss) == pb::STATUS_CODE_DATA_LOSS);
static_assert(static_cast<int>(yt::StatusCode::Unauthenticated) == pb::STATUS_CODE_UNAUTHENTICATED);
}  // anonymous namespace

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

    // HTTP/2 keepalive (#376 PR 1c-4 commit-(iii) prerequisite, closes
    // SRE-1 from PR 1c-4 governance round 2).
    //
    // Pre-PR-1c-4 the agent built a legacy `grpc::Channel` for Subscribe +
    // DownloadUpdate with these exact args at agent.cpp:643-647. PR 1c-4
    // commit (ii) lifted both RPCs onto `transport::Channel`; commit (iii)
    // will delete the legacy block. Without the args resident inside this
    // backend, the post-(iii) state would have NO keepalive on any agent
    // RPC — Heartbeat at 30 s is the next-coarsest liveness signal, which
    // is too slow to detect a NAT/LB idle timer in the 15-30 s range
    // common to corporate transparent proxies. SRE-1 surfaced this as a
    // forward-looking blocker.
    //
    // Values match the legacy agent.cpp settings exactly so commit (iii)
    // is a pure deletion with no behavioural change:
    //   * KEEPALIVE_TIME_MS = 60000        — PING every 60 s of idle.
    //   * KEEPALIVE_TIMEOUT_MS = 20000     — PING ack must arrive in 20 s.
    //   * PERMIT_WITHOUT_CALLS = 1         — PING even when no active RPC.
    //   * MAX_PINGS_WITHOUT_DATA = 0       — unlimited PINGs without data.
    //
    // PR 1c-4 design grilling Q6 chose to keep these inside the gRPC
    // backend rather than expose them in the abstraction surface; msquic
    // (PR 3) has its own keepalive primitives and will configure them
    // independently. No public API change; values match historical agent
    // behaviour 1:1.
    args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, 60000);
    args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 20000);
    args.SetInt(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);
    args.SetInt(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, 0);

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
    if (channel_) {
        generic_stub_ = std::make_unique<::grpc::GenericStub>(channel_);
    }

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

namespace {

// Map gRPC's status enum to ours. Numeric values are FROZEN to match;
// the static_assert block above pins this at compile time. Helpers
// for ByteBuffer<->string and method-name validation live in
// grpc_internal_helpers.hpp.
//
// gRPC docs say status codes are in the range [0, 16] but a future
// gRPC revision could deliver a higher numeric value (or a corrupted
// trailer could decode to one). Out-of-range values collapse to
// StatusCode::Unknown rather than UB-via-blind-cast (governance round 5
// cpp S3): the StatusCode enum is `: int` so a stray cast is not UB
// today, but the result violates the documented closed-set semantics
// and downstream code that switches on the enum would silently miss
// the value.
StatusCode map_grpc_status(::grpc::StatusCode g) noexcept {
    const int v = static_cast<int>(g);
    if (v < static_cast<int>(StatusCode::Ok) ||
        v > static_cast<int>(StatusCode::Unauthenticated)) {
        return StatusCode::Unknown;
    }
    return static_cast<StatusCode>(v);
}

}  // namespace

CallResult GrpcChannel::unary(std::string_view method, const CallContext& ctx,
                              const SerializableMessage& request,
                              SerializableMessage& response) {
    CallResult r;
    // construction_error_ is built from `make_grpc_channel_credentials`
    // detail strings which already carry the `"Credentials: "` prefix
    // (sibling-prefix per the Status::detail contract block).
    if (!construction_error_.empty()) {
        r.status = {StatusCode::Unauthenticated, construction_error_};
        return r;
    }
    if (closed_.load(std::memory_order_acquire)) {
        r.status = {StatusCode::Cancelled, "transport: channel closed"};
        return r;
    }
    if (!method_name_well_formed(method)) {
        r.status = {StatusCode::InvalidArgument,
                    "transport: method name fails validation contract"};
        return r;
    }
    if (!generic_stub_ || !channel_) {
        r.status = {StatusCode::Unavailable,
                    "transport: channel not constructed"};
        return r;
    }

    // Serialize request bytes via the SerializableMessage adapter.
    std::string req_bytes;
    if (!request.serialize(req_bytes)) {
        r.status = {StatusCode::Internal,
                    "transport: request serialize failed"};
        return r;
    }
    if (req_bytes.size() > kAbsoluteMaxFrameSize) {
        // Outbound frame cap (absolute ceiling on the client side; per-listener
        // cap on the server side via ListenerOptions::max_frame_size).
        r.status = {StatusCode::ResourceExhausted,
                    "transport: request exceeds kAbsoluteMaxFrameSize"};
        return r;
    }

    ::grpc::ByteBuffer req_buf  = string_to_byte_buffer(req_bytes);
    ::grpc::ByteBuffer resp_buf;

    ::grpc::ClientContext gctx;
    // Capture monotonic time at deadline arming so an NTP step during the
    // in-flight window can be detected on DeadlineExceeded returns. gRPC's
    // ClientContext::set_deadline only accepts system_clock::time_point
    // (grpcpp/support/time.h:46-47 deletes other clock overloads), so the
    // wire deadline is system-clock based and a backward step expires it
    // early. See `docs/ci-cpp23-troubleshooting.md` "NTP step risk" (#914).
    const auto deadline_armed_at = std::chrono::steady_clock::now();
    if (ctx.deadline > std::chrono::milliseconds::zero()) {
        gctx.set_deadline(std::chrono::system_clock::now() + ctx.deadline);
    }
    for (const auto& [k, v] : ctx.metadata) {
        // Bound checks per the proto contract — defensive, since the
        // CallContext is caller-controlled and an oversized metadata
        // value would be rejected at the server's serialise time anyway.
        if (k.size() > kMaxMetadataKeySize ||
            v.size() > kMaxMetadataValueSize) {
            r.status = {StatusCode::ResourceExhausted,
                        "transport: metadata oversized"};
            return r;
        }
        gctx.AddMetadata(k, v);
    }

    // Cancellation hook: when the caller's stop_token signals stop, call
    // gctx.TryCancel() so the in-flight RPC observes a Cancelled status.
    // The optional<stop_callback> ensures the hook is unregistered on
    // function exit (RAII).
    auto cancel_lambda = [&gctx]() noexcept { gctx.TryCancel(); };
    using cancel_cb_t = std::stop_callback<decltype(cancel_lambda)>;
    std::optional<cancel_cb_t> cancel_hook;
    if (ctx.cancel.stop_possible()) {
        cancel_hook.emplace(ctx.cancel, cancel_lambda);
    }

    if (metric_sink_) {
        metric_sink_->on_stream_opened("grpc", method);
        metric_sink_->on_bytes_sent("grpc", req_bytes.size());
    }

    // Synchronous wrapper around the callback-based UnaryCall API. The
    // gRPC scheduler invokes on_completion on an internal thread; the
    // promise/future hands off the resulting status to the caller
    // thread. ByteBuffer storage is on the stack and survives until
    // the callback fires (we wait on .get() before returning).
    std::promise<::grpc::Status> done_promise;
    auto done_future = done_promise.get_future();
    generic_stub_->UnaryCall(
        &gctx, std::string{method}, /*options=*/{}, &req_buf, &resp_buf,
        [&done_promise](::grpc::Status s) { done_promise.set_value(std::move(s)); });
    ::grpc::Status g_status = done_future.get();

    r.status.code = map_grpc_status(g_status.error_code());
    // SYMMETRIC scrub on receive (Status::detail contract block in
    // transport.hpp). The remote peer's `grpc-message` bytes are
    // attacker-controlled when the agent talks to a non-Yuzu peer;
    // unsanitised inbound detail flowing into TransportMetricSink
    // labels, audit envelope rows, or SSE-rendered status fragments
    // is the UP-41 / sec-1 cluster (governance round 5).
    r.status.detail = sanitise_status_detail(g_status.error_message());

    // NTP-step sanity log (#914 / UP-108). On a DeadlineExceeded return,
    // compare elapsed steady-clock time against the configured deadline.
    // If steady-elapsed is meaningfully shorter than the deadline (slack:
    // 50 ms covers normal scheduler jitter), the wall-clock deadline
    // fired early — the most likely cause is a backward system_clock NTP
    // step during the in-flight window. The log is incident-triage only;
    // user-visible status remains DeadlineExceeded.
    if (r.status.code == StatusCode::DeadlineExceeded &&
        ctx.deadline > std::chrono::milliseconds::zero()) {
        const auto elapsed_steady =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - deadline_armed_at);
        constexpr auto kSanitySlack = std::chrono::milliseconds(50);
        if (elapsed_steady + kSanitySlack < ctx.deadline) {
            spdlog::warn(
                "transport: deadline fired but elapsed steady time was {} ms < "
                "expected {} ms (method='{}') — possible system_clock NTP step",
                elapsed_steady.count(), ctx.deadline.count(), method);
        }
    }

    // Copy trailing metadata for the caller (per the abstraction
    // contract — initial vs trailing distinction lives in transport.hpp).
    for (const auto& [k, v] : gctx.GetServerTrailingMetadata()) {
        r.trailing_metadata.emplace(std::string(k.data(), k.size()),
                                    std::string(v.data(), v.size()));
    }

    if (g_status.ok()) {
        // Even a successful gRPC status carries a (typically empty)
        // detail string. Already scrubbed above; retained on success.
        std::string resp_bytes;
        if (!byte_buffer_to_string(resp_buf, resp_bytes)) {
            r.status = {StatusCode::DataLoss,
                        "transport: response ByteBuffer dump failed"};
        } else {
            // Report bytes received BEFORE the frame-cap / parse gates so
            // an oversized or malformed response still increments the
            // counter — operators monitoring traffic want absolute bytes
            // even on failure (governance HP-1).
            if (metric_sink_) {
                metric_sink_->on_bytes_received("grpc", resp_bytes.size());
            }
            if (resp_bytes.size() > kAbsoluteMaxFrameSize) {
                r.status = {StatusCode::ResourceExhausted,
                            "transport: response exceeds kAbsoluteMaxFrameSize"};
            } else if (!response.parse(resp_bytes)) {
                // Per the parse() contract: false = wire corruption, fatal
                // for the call. Translate to DataLoss.
                r.status = {StatusCode::DataLoss,
                            "transport: response parse failed"};
            }
        }
    }

    if (metric_sink_) {
        metric_sink_->on_stream_closed("grpc", method, r.status);
    }
    return r;
}

// =====================================================================
// GrpcBidiStream — client-side bidi stream over grpc::GenericStub.
// =====================================================================
//
// Implementation strategy:
//   * Per-stream `grpc::CompletionQueue` + worker thread. Avoids
//     coupling stream lifetimes to a shared CQ.
//   * Each gRPC async op (StartCall / Write / Read / WritesDone /
//     Finish) is posted with a distinct tag pointer. The worker pumps
//     `cq_.Next()`, decodes the tag, sets the matching `optional<bool>`
//     under `mtx_`, and notifies `cv_`.
//   * The public BidiStream surface (write/read/writes_done/cancel/
//     final_status) blocks on `cv_` until the matching event fires.
//     Threading contract per transport.hpp: single-reader + single-
//     writer concurrent. At most one Read tag and one Write tag are
//     in flight at a time.
//   * On terminal-state transitions the worker thread exits via
//     `cq_.Shutdown()`; the dtor joins it.
class GrpcBidiStream final : public BidiStream {
public:
    GrpcBidiStream(::grpc::GenericStub* stub, std::string method,
                   const CallContext& ctx,
                   std::shared_ptr<TransportMetricSink> sink)
        : sink_(std::move(sink)), method_(std::move(method)) {
        if (ctx.deadline > std::chrono::milliseconds::zero()) {
            gctx_.set_deadline(std::chrono::system_clock::now() + ctx.deadline);
        }
        for (const auto& [k, v] : ctx.metadata) {
            // CallContext metadata is caller-controlled. Defensive cap
            // mirrors the unary path; oversize is reported on first op.
            if (k.size() > kMaxMetadataKeySize ||
                v.size() > kMaxMetadataValueSize) {
                construction_error_ = "transport: metadata oversized";
                continue;
            }
            gctx_.AddMetadata(k, v);
        }
        if (ctx.cancel.stop_possible()) {
            cancel_hook_.emplace(ctx.cancel, CancelOnStop{this});
        }

        rw_ = stub->PrepareCall(&gctx_, method_, &cq_);
        if (!rw_) {
            // PrepareCall failure path. Without explicit short-circuit
            // bookkeeping, any subsequent write/read/writes_done would
            // hang forever in `await_started()` (start_done_ never
            // arrives because no StartCall is posted), and the dtor's
            // `ensure_finished()` would deadlock waiting for a
            // finish_done_ that no Finish ever produces (governance
            // UP-5 / UP-6). Seed terminal-state flags here under no
            // lock — the worker hasn't spawned yet — so every waiter
            // observes the failure and returns immediately.
            construction_error_ = "transport: PrepareCall returned null";
            start_done_         = false;
            finishing_          = true;
            finished_           = true;
            finish_done_        = false;
            cq_.Shutdown();
        }
        // Member metric_emitted_open_ records whether on_stream_opened
        // fired so the dtor's on_stream_closed mirror is symmetric
        // (governance sec-L3). On the PrepareCall-null path we skip
        // both halves; on the success path both fire.
        worker_ = std::thread([this] { worker_loop(); });
        if (rw_) {
            rw_->StartCall(reinterpret_cast<void*>(kTagStart));
            if (sink_) {
                sink_->on_stream_opened("grpc", method_);
                metric_emitted_open_ = true;
            }
        }
    }

    ~GrpcBidiStream() override {
        try {
            // Must terminate the call so cq_ can be shut down cleanly.
            // If neither writes_done nor final_status was reached, the
            // call is still live — force it down via TryCancel + Finish.
            ensure_finished();
        } catch (...) {
            // dtor: swallow
        }
        cq_.Shutdown();
        if (worker_.joinable()) worker_.join();
        if (sink_ && metric_emitted_open_) {
            sink_->on_stream_closed("grpc", method_, final_yt_status_);
        }
    }

    bool write(const SerializableMessage& msg) override {
        if (!rw_ || !construction_error_.empty()) return false;
        std::string bytes;
        if (!msg.serialize(bytes)) return false;
        if (bytes.size() > kAbsoluteMaxFrameSize) return false;
        if (!await_started()) return false;

        std::unique_lock<std::mutex> lock(mtx_);
        if (cancelled_ || writes_done_called_ || finished_) return false;
        write_done_.reset();
        write_buf_ = string_to_byte_buffer(bytes);
        rw_->Write(write_buf_, reinterpret_cast<void*>(kTagWrite));
        cv_.wait(lock, [this] {
            return write_done_.has_value() || cancelled_;
        });
        if (cancelled_) return false;
        const bool ok = *write_done_;
        if (ok && sink_) sink_->on_bytes_sent("grpc", bytes.size());
        return ok;
    }

    bool read(SerializableMessage& msg,
              std::chrono::milliseconds deadline =
                  std::chrono::milliseconds::zero()) override {
        if (!rw_ || !construction_error_.empty()) return false;
        if (!await_started()) return false;

        ::grpc::ByteBuffer local_buf;
        {
            std::unique_lock<std::mutex> lock(mtx_);
            if (cancelled_ || finished_) return false;
            read_done_.reset();
            read_buf_.Clear();
            rw_->Read(&read_buf_, reinterpret_cast<void*>(kTagRead));
            const auto pred = [this] {
                return read_done_.has_value() || cancelled_;
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
                // cancelled_, then TryCancel via cancel() so the
                // worker_loop drains the cq events normally and the
                // dtor's ensure_finished() proceeds. Lock is released
                // implicitly by cancel(); we re-test cancelled_ below.
                if (!cv_.wait_for(lock, deadline, pred)) {
                    read_deadline_exceeded_ = true;
                    cancelled_              = true;
                    cv_.notify_all();
                    lock.unlock();
                    gctx_.TryCancel();
                    return false;
                }
            } else {
                cv_.wait(lock, pred);
            }
            if (cancelled_) return false;
            if (!*read_done_) return false;  // peer half-close / cancel
            local_buf = std::move(read_buf_);
        }
        std::string bytes;
        if (!byte_buffer_to_string(local_buf, bytes)) return false;
        if (bytes.size() > kAbsoluteMaxFrameSize) return false;
        if (sink_) sink_->on_bytes_received("grpc", bytes.size());
        return msg.parse(bytes);
    }

    void writes_done() override {
        if (!rw_ || !construction_error_.empty()) return;
        if (!await_started()) return;
        std::unique_lock<std::mutex> lock(mtx_);
        if (cancelled_ || writes_done_called_ || finished_) return;
        writes_done_called_ = true;
        writes_done_done_.reset();
        rw_->WritesDone(reinterpret_cast<void*>(kTagWritesDone));
        cv_.wait(lock, [this] {
            return writes_done_done_.has_value() || cancelled_;
        });
    }

    Status final_status() override {
        if (!construction_error_.empty()) {
            return Status{StatusCode::Unauthenticated, construction_error_};
        }
        if (!rw_) return Status{StatusCode::Unavailable, "transport: stream not started"};

        std::unique_lock<std::mutex> lock(mtx_);
        if (!finished_) {
            // Drain reads until peer half-closes so trailing-status is
            // valid. We do not loop on Read here — that's the caller's
            // job (per transport.hpp: final_status() is called from the
            // reader thread after read() has returned false). We just
            // post Finish if not already, and wait for it.
            if (!finishing_) {
                finishing_ = true;
                finish_done_.reset();
                rw_->Finish(&final_grpc_status_,
                            reinterpret_cast<void*>(kTagFinish));
            }
            cv_.wait(lock, [this] { return finish_done_.has_value(); });
            finished_ = true;
            final_yt_status_.code = map_grpc_status_local(final_grpc_status_.error_code());
            // SYMMETRIC inbound scrub of Status::detail (transport.hpp
            // contract block); sec-1 / UP-41 / cons-G4-2.
            final_yt_status_.detail =
                sanitise_status_detail(final_grpc_status_.error_message());
            for (const auto& [k, v] : gctx_.GetServerTrailingMetadata()) {
                trailing_metadata_.emplace(
                    std::string(k.data(), k.size()),
                    std::string(v.data(), v.size()));
            }
            // BidiStream contract: if read() observed an idle-deadline
            // expiry, final_status() reports DeadlineExceeded regardless
            // of what the wire status says (which is invariably
            // Cancelled because we TryCancel'd from the read path).
            // #902 / UP-8.
            if (read_deadline_exceeded_) {
                final_yt_status_ = Status{
                    StatusCode::DeadlineExceeded,
                    "transport: bidi read deadline exceeded"};
            }
        }
        return final_yt_status_;
    }

    const std::map<std::string, std::string>& trailing_metadata() const override {
        return trailing_metadata_;
    }

    void cancel() override {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            if (cancelled_) return;
            cancelled_ = true;
        }
        gctx_.TryCancel();
        cv_.notify_all();
    }

private:
    enum : uintptr_t {
        kTagStart      = 1,
        kTagWrite      = 2,
        kTagRead       = 3,
        kTagWritesDone = 4,
        kTagFinish     = 5,
    };

    struct CancelOnStop {
        GrpcBidiStream* self;
        void operator()() const noexcept {
            if (self) self->cancel();
        }
    };

    static StatusCode map_grpc_status_local(::grpc::StatusCode g) noexcept {
        const int v = static_cast<int>(g);
        if (v < static_cast<int>(StatusCode::Ok) ||
            v > static_cast<int>(StatusCode::Unauthenticated)) {
            return StatusCode::Unknown;
        }
        return static_cast<StatusCode>(v);
    }

    bool await_started() {
        std::unique_lock<std::mutex> lock(mtx_);
        cv_.wait(lock, [this] {
            return start_done_.has_value() || cancelled_;
        });
        if (cancelled_) return false;
        return *start_done_;
    }

    void ensure_finished() {
        // Called from dtor. If the caller never reached final_status(),
        // we must terminate the call so cq_ can drain. TryCancel then
        // Finish; wait briefly for the Finish tag.
        bool need_finish = false;
        {
            std::lock_guard<std::mutex> lock(mtx_);
            if (!finished_ && !finishing_) {
                finishing_ = true;
                need_finish = true;
            }
        }
        if (need_finish) {
            gctx_.TryCancel();
            if (rw_) {
                rw_->Finish(&final_grpc_status_,
                            reinterpret_cast<void*>(kTagFinish));
            }
            std::unique_lock<std::mutex> lock(mtx_);
            cv_.wait(lock, [this] { return finish_done_.has_value(); });
            finished_ = true;
        }
    }

    void worker_loop() {
        void* tag = nullptr;
        bool ok = false;
        while (cq_.Next(&tag, &ok)) {
            const auto kind = reinterpret_cast<uintptr_t>(tag);
            std::lock_guard<std::mutex> lock(mtx_);
            switch (kind) {
                case kTagStart:      start_done_       = ok; break;
                case kTagWrite:      write_done_       = ok; break;
                case kTagRead:       read_done_        = ok; break;
                case kTagWritesDone: writes_done_done_ = ok; break;
                case kTagFinish:     finish_done_      = ok; break;
                default:
                    spdlog::error(
                        "yuzu::transport: GrpcBidiStream worker saw "
                        "unknown tag {}", kind);
                    break;
            }
            cv_.notify_all();
        }
    }

    ::grpc::ClientContext                                    gctx_;
    ::grpc::CompletionQueue                                  cq_;
    std::unique_ptr<::grpc::GenericClientAsyncReaderWriter>  rw_;
    std::thread                                              worker_;
    std::shared_ptr<TransportMetricSink>                     sink_;
    std::string                                              method_;
    std::string                                              construction_error_;

    std::mutex                                               mtx_;
    std::condition_variable                                  cv_;
    std::optional<bool>                                      start_done_;
    std::optional<bool>                                      write_done_;
    std::optional<bool>                                      read_done_;
    std::optional<bool>                                      writes_done_done_;
    std::optional<bool>                                      finish_done_;
    bool                                                     finishing_           = false;
    bool                                                     finished_            = false;
    bool                                                     writes_done_called_  = false;
    bool                                                     cancelled_           = false;
    // Set by read() when its idle-read deadline lapses before a frame
    // arrives (#902 / UP-8). final_status() promotes the wire-level
    // Cancelled (from TryCancel) to DeadlineExceeded so the caller can
    // distinguish deadline expiry from external cancel() / peer
    // half-close — matches the BidiStream contract block in
    // transport.hpp.
    bool                                                     read_deadline_exceeded_ = false;
    // governance sec-L3: gauge balance for failed-construction streams.
    // on_stream_opened fires only on the PrepareCall-success path; the
    // dtor's matching on_stream_closed gates on this flag so the gauge
    // does not go negative when a bidi_stream() call fails to construct.
    bool                                                     metric_emitted_open_ = false;

    ::grpc::ByteBuffer                                       write_buf_;
    ::grpc::ByteBuffer                                       read_buf_;
    ::grpc::Status                                           final_grpc_status_;
    Status                                                   final_yt_status_;
    std::map<std::string, std::string>                       trailing_metadata_;

    std::optional<std::stop_callback<CancelOnStop>>          cancel_hook_;
};

std::unique_ptr<BidiStream> GrpcChannel::bidi_stream(
    std::string_view method, const CallContext& ctx) {
    if (!construction_error_.empty()) {
        // Construction-time error must surface via final_status() per
        // BidiStream contract; we still return a usable wrapper so the
        // caller's read/write paths fail uniformly.
        struct DeadStream final : BidiStream {
            std::string err;
            std::map<std::string, std::string> empty_md;
            bool write(const SerializableMessage&) override { return false; }
            bool read(SerializableMessage&,
                      std::chrono::milliseconds = std::chrono::milliseconds::zero())
                      override { return false; }
            void writes_done() override {}
            Status final_status() override { return {StatusCode::Unauthenticated, err}; }
            const std::map<std::string, std::string>& trailing_metadata() const override {
                return empty_md;
            }
            void cancel() override {}
        };
        auto d = std::make_unique<DeadStream>();
        d->err = construction_error_;
        return d;
    }
    if (closed_.load(std::memory_order_acquire)) return nullptr;
    if (!method_name_well_formed(method)) return nullptr;
    if (!generic_stub_ || !channel_) return nullptr;
    return std::make_unique<GrpcBidiStream>(generic_stub_.get(),
                                            std::string{method}, ctx,
                                            metric_sink_);
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
            "grpc", {StatusCode::Ok, "transport: channel closed"});
    }
    // grpc::Channel has no explicit close; dropping the shared_ptr is
    // sufficient. Active calls observe transient FAILURE on next op.
    channel_.reset();
}

}  // namespace yuzu::transport::grpc_backend
