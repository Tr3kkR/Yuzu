// SPDX-License-Identifier: Apache-2.0
// yuzu::transport — RPC transport abstraction.
//
// Two implementations live behind this header:
//   * grpc_transport — current gRPC over HTTP/2 implementation
//   * msquic_transport — QUIC implementation introduced in PR 3 of #376
//
// Wire format is protobuf in both cases. Service handlers above this layer
// see only the `Channel` / `ServerListener` / `BidiStream` surfaces; they
// never reference grpc:: or msquic:: types directly.
//
// See ADR-0001 (docs/adrs/0001-quic-transport-msquic-quicer.md) for the
// rationale and the rejected alternatives.

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::transport {

// StatusCode mirrors the canonical gRPC codes one-for-one. The numeric
// values match google.rpc.Code so existing error-mapping code in the rest
// of the codebase (server/core/src/error_codes.hpp) continues to work
// unchanged.
enum class StatusCode : int {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
};

struct Status {
    StatusCode code = StatusCode::Ok;
    std::string detail;

    bool ok() const noexcept { return code == StatusCode::Ok; }
};

// Endpoint identifies a host:port pair. The host is parsed lazily by the
// transport implementation — it can be an IP literal, a DNS name, or
// (for the gRPC implementation) a unix-socket path.
struct Endpoint {
    std::string host;
    uint16_t port = 0;
};

// Credentials holds PEM-encoded mTLS material. The reload callback, when
// non-null, is invoked by the transport before each new connection
// (client) or each handshake (server) to allow rotation without
// reconstructing the Channel/ServerListener. This mirrors the
// cert_reloader hook used by the current gRPC code.
struct Credentials {
    std::string client_cert_pem; // empty on server-side or in plaintext mode
    std::string client_key_pem;  // empty on server-side or in plaintext mode
    std::string ca_cert_pem;     // empty in plaintext mode
    std::string server_cert_pem; // empty on client-side
    std::string server_key_pem;  // empty on client-side

    // Verify peer cert? Server-side: require client cert. Client-side:
    // require server cert chains to a trusted root. False ⇒ TOFU /
    // plaintext, only allowed for tests.
    bool verify_peer = true;

    // Reload hook. If set, the transport calls this before each connection
    // (client) or each new TLS handshake (server) to obtain freshly-loaded
    // material. The returned Credentials replaces the in-memory copy for
    // that connection only.
    std::function<Credentials()> reload;
};

// CallContext travels with a single RPC invocation (client side) or a
// single dispatched call (server side). The deadline is wall-clock relative
// to call start; cancel propagates from caller-side stop_source.
struct CallContext {
    std::chrono::milliseconds deadline = std::chrono::milliseconds::zero();
    std::map<std::string, std::string> metadata;
    std::stop_token cancel;
};

// CallResult carries the trailing status of any completed call. For
// unary RPCs the response message is delivered separately; this only
// reports success/failure.
struct CallResult {
    Status status;
    std::map<std::string, std::string> trailing_metadata;
};

// =====================================================================
// Streams
// =====================================================================
//
// Each streaming primitive carries a typed protobuf message in each
// direction. Messages are templated at call sites; the transport
// implementation serializes/deserializes via protobuf::MessageLite.
//
// All Read*/Write* methods are blocking. Cancellation is via the
// CallContext stop_token.

// SerializableMessage is the minimal contract a stream message must satisfy.
// Both grpc:: generated messages and any future hand-written messages
// satisfy this via protobuf's MessageLite interface; we restate it here
// to avoid leaking <google/protobuf/message_lite.h> into transport.hpp.
//
// Implementations call SerializeToString / ParseFromString on the
// underlying message via a small adapter in the .cpp.
class SerializableMessage {
public:
    virtual ~SerializableMessage() = default;
    virtual bool serialize(std::string& out) const = 0;
    virtual bool parse(std::string_view in) = 0;
};

// BidiStream is the server-streaming, client-streaming, and bidi-streaming
// surface — the most general shape. The other two streaming kinds are
// degenerate cases (read or write half disabled).
//
// On the client side, a BidiStream is owned by the caller and obtained
// from `Channel::bidi_stream(...)`. On the server side, the transport
// constructs a BidiStream and hands it to the registered handler.
class BidiStream {
public:
    virtual ~BidiStream() = default;

    // Write a frame. Blocks until the frame is accepted into the transport
    // buffer (NOT until it lands on the wire). Returns false if the stream
    // has been finished or cancelled.
    virtual bool write(const SerializableMessage& msg) = 0;

    // Read the next frame into msg. Returns true on success, false on
    // half-close from the peer or on cancellation. Use `final_status()`
    // after a false return to learn why.
    virtual bool read(SerializableMessage& msg) = 0;

    // Half-close the writer side (no more outgoing frames). Reader side
    // continues to drain incoming frames until the peer half-closes.
    virtual void writes_done() = 0;

    // Final status of the stream after both halves have closed. Blocks
    // until the trailing-status frame has been received from the peer.
    virtual Status final_status() = 0;

    // Trailing metadata, available after final_status() returns.
    virtual const std::map<std::string, std::string>& trailing_metadata() const = 0;

    // Cancel the stream. Both reads and writes return false thereafter.
    virtual void cancel() = 0;
};

// =====================================================================
// Client-side
// =====================================================================

// UnaryCallback is invoked when an async unary call completes.
using UnaryCallback = std::function<void(CallResult)>;

class Channel {
public:
    virtual ~Channel() = default;

    // Synchronous unary call. The request and response messages are
    // serialized/deserialized by the caller's adapter; the transport
    // sees them only as SerializableMessage.
    virtual CallResult unary(std::string_view method, const CallContext& ctx,
                             const SerializableMessage& request, SerializableMessage& response) = 0;

    // Open a bidi stream. The returned object owns the underlying
    // transport state; destroying it cancels the stream if not finished.
    virtual std::unique_ptr<BidiStream> bidi_stream(std::string_view method,
                                                    const CallContext& ctx) = 0;

    // Wait until the channel is connected to the remote endpoint, or the
    // deadline elapses. Returns true on success.
    virtual bool wait_for_connected(std::chrono::milliseconds deadline) = 0;

    // Close the channel. In-flight calls are cancelled.
    virtual void close() = 0;
};

// =====================================================================
// Server-side
// =====================================================================
//
// Handlers are registered against a method name in the form
// "yuzu.<package>.<service>/<Method>". The same string the client passes
// to Channel::unary or Channel::bidi_stream.

using UnaryHandler = std::function<Status(
    const CallContext& ctx, const SerializableMessage& request, SerializableMessage& response)>;

using BidiStreamHandler = std::function<Status(const CallContext& ctx, BidiStream& stream)>;

class ServerListener {
public:
    virtual ~ServerListener() = default;

    // Register a handler for a unary RPC. The factory functions create
    // fresh request/response message instances per call.
    virtual void
    register_unary(std::string method,
                   std::function<std::unique_ptr<SerializableMessage>()> request_factory,
                   std::function<std::unique_ptr<SerializableMessage>()> response_factory,
                   UnaryHandler handler) = 0;

    // Register a handler for a bidi-streaming RPC.
    virtual void register_bidi_stream(std::string method, BidiStreamHandler handler) = 0;

    // Bind to the given endpoint and start serving. After this call,
    // register_* calls are not allowed.
    virtual std::expected<void, Status> start(const Endpoint& bind, const Credentials& creds) = 0;

    // Block until shutdown() is called. Used by the main thread of
    // server processes.
    virtual void wait_for_shutdown() = 0;

    // Initiate graceful shutdown. In-flight handlers run to completion;
    // new connections are refused. wait_for_shutdown() returns once the
    // last handler exits.
    virtual void shutdown() = 0;
};

// =====================================================================
// Factories
// =====================================================================
//
// Two implementations live in sdk/src/transport/. Selection at runtime
// is via the build-time toggle `-Dtransport=grpc|msquic|both` plus the
// runtime `--transport=grpc|quic|auto` flag (added in PR 5).
//
// Build-time selection is enforced by linking the matching backend lib;
// runtime selection picks among the linked-in factories.

enum class Backend {
    Grpc,
    Msquic,
};

// Construct a client-side channel. Returns nullptr if the requested
// backend is not linked in.
std::unique_ptr<Channel> make_channel(Backend backend, const Endpoint& target,
                                      const Credentials& creds);

// Construct a server-side listener.
std::unique_ptr<ServerListener> make_server_listener(Backend backend);

// String <-> Backend conversion (used by --transport flag parsing).
std::string_view backend_name(Backend b) noexcept;
std::expected<Backend, Status> parse_backend(std::string_view name) noexcept;

} // namespace yuzu::transport
