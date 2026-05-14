// SPDX-License-Identifier: Apache-2.0
// MsquicServerListener — the msquic backend implementation of
// yuzu::transport::ServerListener.
//
// Internal header; consumers see only the abstract interface in
// <yuzu/transport/transport.hpp> and obtain instances via
// make_server_listener(Backend::Msquic).
//
// #376 PR 3, increment 2: real listener bring-up — ConfigurationOpen +
// credential load + ListenerStart + the three msquic callback levels +
// HandshakeHello dispatch + unary handler invocation on a worker pool.
// Increment 3 adds the bidi path; increment 7 adds the bounded
// dispatcher-pool saturation contract.

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "msquic.h"

#include "msquic_worker_pool.hpp"
#include "yuzu/transport/transport.hpp"

namespace yuzu::transport::msquic_backend {

// Per-stream server-side call state. Defined in msquic_listener.cpp — the
// listener only needs to hold shared_ptrs to live calls.
struct ServerStreamCall;

// msquic callback trampolines (defined in msquic_listener.cpp). Declared
// at namespace scope so the friend declarations below refer to these.
QUIC_STATUS QUIC_API msquic_listener_callback(HQUIC, void*,
                                              QUIC_LISTENER_EVENT*);
QUIC_STATUS QUIC_API msquic_conn_callback(HQUIC, void*,
                                          QUIC_CONNECTION_EVENT*);
QUIC_STATUS QUIC_API msquic_stream_callback(HQUIC, void*, QUIC_STREAM_EVENT*);

class MsquicServerListener final : public ServerListener {
public:
    MsquicServerListener();
    ~MsquicServerListener() override;

    MsquicServerListener(const MsquicServerListener&)            = delete;
    MsquicServerListener& operator=(const MsquicServerListener&) = delete;

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

    // Throws std::invalid_argument if `method` fails the HandshakeHello
    // method-name contract — same behaviour as the gRPC backend.
    void enforce_method_or_die(const std::string& method);

    // msquic callback trampolines need to reach back into the listener.
    friend QUIC_STATUS QUIC_API msquic_listener_callback(
        HQUIC, void*, QUIC_LISTENER_EVENT*);
    friend QUIC_STATUS QUIC_API msquic_conn_callback(
        HQUIC, void*, QUIC_CONNECTION_EVENT*);
    friend QUIC_STATUS QUIC_API msquic_stream_callback(
        HQUIC, void*, QUIC_STREAM_EVENT*);

    // Called from the stream callback once a HandshakeHello has been
    // parsed: resolves `method` to a registered handler and primes the
    // ServerStreamCall, or sends a TrailingStatus rejection.
    void dispatch_stream_call(ServerStreamCall* call, const std::string& method);

    // Registry lifetime helpers for ServerStreamCall shared_ptrs.
    void track_stream(HQUIC stream, std::shared_ptr<ServerStreamCall> call);
    void untrack_stream(HQUIC stream);

    // Effective per-stream frame cap (opts_.max_frame_size or the default).
    std::size_t stream_max_frame() const noexcept;

    // Hand a handler invocation to the worker pool. Returns false if the
    // listener is shutting down (pool gone).
    bool listener_submit(std::function<void()> task);

    mutable std::mutex                       mtx_;
    std::condition_variable                  shutdown_cv_;
    std::map<std::string, UnaryRegistration> unary_handlers_;
    std::map<std::string, BidiStreamHandler> bidi_handlers_;
    ListenerOptions                          opts_;
    Endpoint                                 bound_endpoint_;

    // msquic objects, created in start(), torn down in shutdown()/dtor.
    HQUIC                                    configuration_ = nullptr;
    HQUIC                                    listener_      = nullptr;

    // Handler-dispatch pool — handlers never run on msquic worker threads.
    std::unique_ptr<WorkerPool>              worker_pool_;

    // Live per-stream call state, keyed by the msquic stream handle. The
    // raw ServerStreamCall* is stashed as each stream's msquic context;
    // this map owns the shared_ptr so the call outlives the callbacks.
    std::map<HQUIC, std::shared_ptr<ServerStreamCall>> live_streams_;

    std::atomic<bool>                        started_{false};
    std::atomic<bool>                        shutting_down_{false};
};

}  // namespace yuzu::transport::msquic_backend
