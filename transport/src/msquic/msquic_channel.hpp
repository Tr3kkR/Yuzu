// SPDX-License-Identifier: Apache-2.0
// MsquicChannel — the msquic backend implementation of
// yuzu::transport::Channel.
//
// Internal header; consumers see only the abstract Channel interface in
// <yuzu/transport/transport.hpp> and obtain instances via
// make_channel(Backend::Msquic, ...).
//
// #376 PR 3, increment 2: real client connection establishment +
// synchronous unary RPC over a QUIC stream. The bidi path is still the
// increment-0 skeleton stub (replaced in increment 3); deadlines are
// increment 4; mTLS / server-cert verification is increment 5.

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include "msquic.h"

#include "yuzu/transport/transport.hpp"

namespace yuzu::transport::msquic_backend {

// Per-stream client-side unary call state. Defined in msquic_channel.cpp.
struct ClientUnaryCall;

// msquic client-side callback trampolines (defined in msquic_channel.cpp).
QUIC_STATUS QUIC_API msquic_client_conn_callback(HQUIC, void*,
                                                 QUIC_CONNECTION_EVENT*);
QUIC_STATUS QUIC_API msquic_client_stream_callback(HQUIC, void*,
                                                   QUIC_STREAM_EVENT*);

// Skeleton bidi stream — every operation reports the not-yet-implemented
// state. Replaced by the real StreamState-backed implementation in
// increment 3.
class MsquicBidiStream final : public BidiStream {
public:
    bool write(const SerializableMessage& msg,
               std::chrono::milliseconds deadline =
                   std::chrono::milliseconds::zero()) override;
    bool read(SerializableMessage& msg,
              std::chrono::milliseconds deadline =
                  std::chrono::milliseconds::zero()) override;
    void writes_done() override;
    Status final_status() override;
    const std::map<std::string, std::string>& trailing_metadata() const override;
    void cancel() override;

private:
    std::map<std::string, std::string> trailing_metadata_;
};

class MsquicChannel final : public Channel {
public:
    MsquicChannel(Endpoint target, Credentials creds, BackoffPolicy backoff,
                  std::shared_ptr<TransportMetricSink> metric_sink);
    ~MsquicChannel() override;

    MsquicChannel(const MsquicChannel&)            = delete;
    MsquicChannel& operator=(const MsquicChannel&) = delete;

    CallResult unary(std::string_view method, const CallContext& ctx,
                     const SerializableMessage& request,
                     SerializableMessage& response) override;

    std::unique_ptr<BidiStream> bidi_stream(std::string_view method,
                                            const CallContext& ctx) override;

    bool wait_for_connected(std::chrono::milliseconds deadline) override;

    void close() override;

private:
    enum class ConnState { Idle, Connecting, Connected, Failed };

    // msquic callback trampolines reach back into the channel.
    friend QUIC_STATUS QUIC_API msquic_client_conn_callback(
        HQUIC, void*, QUIC_CONNECTION_EVENT*);
    friend QUIC_STATUS QUIC_API msquic_client_stream_callback(
        HQUIC, void*, QUIC_STREAM_EVENT*);

    // Establish the connection if not already up. `deadline` zero means
    // wait indefinitely. Returns the resolved Status (Ok == connected).
    Status connect_and_wait(std::chrono::milliseconds deadline);

    void untrack_call(HQUIC stream);

    Endpoint                             target_;
    Credentials                          creds_;
    BackoffPolicy                        backoff_;
    std::shared_ptr<TransportMetricSink> metric_sink_;

    std::mutex                           mtx_;
    std::condition_variable              conn_cv_;
    ConnState                            conn_state_ = ConnState::Idle;
    Status                               conn_error_;  // valid when Failed

    HQUIC                                configuration_ = nullptr;
    HQUIC                                connection_    = nullptr;

    // Live per-stream unary calls, keyed by the msquic stream handle.
    std::map<HQUIC, std::shared_ptr<ClientUnaryCall>> live_calls_;

    std::atomic<bool>                    closed_{false};
};

}  // namespace yuzu::transport::msquic_backend
