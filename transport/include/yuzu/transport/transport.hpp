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
//
// =====================================================================
// Module placement
// =====================================================================
// This header is intentionally NOT in `sdk/include/yuzu/`. The SDK is
// the C-ABI plugin contract (plugin.h / plugin.hpp); plugins have no
// business opening RPC channels or registering service handlers. The
// transport interface is internal: agent and server cores link it; no
// out-of-tree consumer is permitted.
//
// =====================================================================
// ABI stability commitment
// =====================================================================
// This is INTERNAL ABI. It is NOT stable across yuzu versions. Adding a
// new pure-virtual to Channel/ServerListener/BidiStream/SerializableMessage
// in any future version IS a breaking change to in-tree consumers and
// requires re-linking every TU that consumes them. There is no
// out-of-tree consumer commitment. If a future need arises for a stable
// transport ABI exposed to external code, the plan is to wrap a stable
// C ABI around this surface (same pattern as plugin.h / plugin.hpp).

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

// =====================================================================
// Wire-protocol invariants (cross-implementation)
// =====================================================================
//
// Both grpc_transport and msquic_transport satisfy the same external
// invariants:
//
// 1. Length-prefixed framing on QUIC: each protobuf message in either
//    direction is preceded by a 4-byte big-endian length. The length
//    MUST NOT exceed the configured maximum frame size (default
//    `kDefaultMaxFrameSize` = 4 MiB; per-listener override via
//    `ListenerOptions::max_frame_size`; absolute ceiling
//    `kAbsoluteMaxFrameSize` = 64 MiB). Receivers enforce this BEFORE
//    allocating any per-frame buffer; an oversized length triggers
//    stream cancellation with StatusCode::ResourceExhausted
//    and an audit event. (gRPC implementation inherits HTTP/2 frame
//    bounds from the gRPC library; the bound here is the application
//    cap, distinct from the transport cap.)
//
// 2. Wire-byte equivalence between grpc_transport and the pre-#376
//    hand-rolled gRPC code: PR 1 (gRPC lift) MUST produce byte-identical
//    wire output to today's `agent_service_impl.cpp` / `server.cpp`
//    code. The framing primitives in this header are QUIC-only; the
//    grpc_transport implementation does NOT use TrailingStatus or
//    HandshakeHello on the wire — those are msquic-only envelopes.
//
// 3. Status code wire-stability: the numeric values of StatusCode below
//    are FROZEN to match google.rpc.Code / grpc::StatusCode. A
//    static_assert in the .cpp pins this to the proto enum so a future
//    drift fails compilation, not silently mis-routes traffic.

// Default maximum size of a single framed protobuf message accepted
// by the transport layer. Matches the gRPC library default (4 MiB) so
// PR 1 (gRPC lift) does not silently widen the receive attack surface
// relative to the pre-#376 codebase. Frames larger than this are
// rejected at the length-prefix stage with StatusCode::ResourceExhausted;
// the stream is cancelled and an audit event is emitted.
//
// Operators who legitimately need larger frames (e.g. fleet-wide
// inventory aggregation reports) override on a per-listener basis via
// `ListenerOptions::max_frame_size` and on a per-channel basis via
// `BackoffPolicy`'s sibling `ChannelOptions` (added if/when a per-
// connection cap is needed; today none of the legitimate Yuzu RPCs
// exceed the default).
//
// Hard ceiling — implementations MUST refuse to be configured higher
// than `kAbsoluteMaxFrameSize` regardless of operator request.
inline constexpr std::size_t kDefaultMaxFrameSize  = 4 * 1024 * 1024;   // 4 MiB
inline constexpr std::size_t kAbsoluteMaxFrameSize = 64 * 1024 * 1024;  // 64 MiB

// Maximum size of a metadata key or value. Oversized metadata triggers
// StatusCode::ResourceExhausted at serialise time, BEFORE bytes are
// written to the wire (so a misbehaving sender cannot DoS a peer).
inline constexpr std::size_t kMaxMetadataKeySize   = 256;
inline constexpr std::size_t kMaxMetadataValueSize = 4096;
inline constexpr std::size_t kMaxMetadataEntries   = 64;

// Maximum size of HandshakeHello.method.
inline constexpr std::size_t kMaxMethodSize = 256;

// =====================================================================
// Status types
// =====================================================================

// StatusCode mirrors the canonical gRPC codes one-for-one. The numeric
// values match google.rpc.Code so existing error-mapping code in the rest
// of the codebase (server/core/src/error_codes.hpp) continues to work
// unchanged. WIRE-STABLE — see the wire-stability commitment in
// transport.proto and the static_assert in the transport library .cpp.
enum class StatusCode : int {
    Ok                 = 0,
    Cancelled          = 1,
    Unknown            = 2,
    InvalidArgument    = 3,
    DeadlineExceeded   = 4,
    NotFound           = 5,
    AlreadyExists      = 6,
    PermissionDenied   = 7,
    ResourceExhausted  = 8,
    FailedPrecondition = 9,
    Aborted            = 10,
    OutOfRange         = 11,
    Unimplemented      = 12,
    Internal           = 13,
    Unavailable        = 14,
    DataLoss           = 15,
    Unauthenticated    = 16,
};

// Status::detail is ALWAYS transmitted to the remote peer over the
// wire (gRPC carries it as the `grpc-message` HTTP/2 trailer). Treat
// detail as a CLIENT-FACING string:
//
//   * Do not embed internal memory addresses, file paths, raw exception
//     messages from internal libraries (DB driver, filesystem, OS), or
//     any deployment-internal state.
//   * For exception-driven error paths, the transport's dispatcher
//     replaces a thrown std::exception with the static literal
//     "handler raised exception" on the wire (and "handler raised
//     non-std exception" for non-std throws). The original e.what()
//     text is logged server-side at error level and never crosses the
//     process boundary. Application handlers wishing to deliver
//     caller-diagnosable detail must populate Status::detail
//     explicitly with a sanitised message.
//   * Transport-internal detail strings (returned by the transport
//     layer itself, not by application handlers) carry either the
//     `"transport: "` prefix or, for credentials-construction errors,
//     the `"Credentials: "` sub-prefix. Application-handler-returned
//     details carry neither. Operators grep status records to tell
//     the three apart.
//   * Detail must be ASCII printable; non-printable / non-ASCII bytes
//     are scrubbed to '?'. NUL bytes specifically would be silently
//     mangled by gRPC's HTTP/2 trailer encoding (governance UP-22).
//     The total size is capped at 1024 bytes, INCLUDING any
//     `"...[truncated]"` marker; oversize input is truncated to fit.
//
// SYMMETRIC scrub obligation. Implementations MUST apply the same
// length and printable-byte sanitisation BOTH to detail strings produced
// locally (outbound) AND to detail strings received from the peer
// (inbound) before surfacing them via CallResult::status, BidiStream
// trailing status, or any TransportMetricSink callback. Receivers do
// not trust the peer's adherence — a malicious or buggy peer can
// otherwise feed control bytes / oversize blobs into Prometheus label
// cardinality, audit-log rows, and dashboard SSE renders. The shared
// helper at `transport/include/yuzu/transport/detail/sanitise.hpp`
// (`yuzu::transport::sanitise_status_detail`) is the only sanctioned
// implementation; both backends must route through it.
struct Status {
    StatusCode code = StatusCode::Ok;
    std::string detail;

    bool ok() const noexcept { return code == StatusCode::Ok; }
};

// =====================================================================
// Endpoint
// =====================================================================
//
// Endpoint identifies a host:port pair. The host is a DNS name OR an IP
// literal (v4 or v6). Unix-socket paths are NOT accepted by either
// backend; the gRPC-only legacy support for them was unused and is
// deliberately dropped here.
struct Endpoint {
    std::string host;
    uint16_t    port = 0;
};

// =====================================================================
// Credentials
// =====================================================================
//
// Holds PEM-encoded mTLS material plus protocol selectors that mirror
// every relevant knob the existing gRPC code path uses today
// (agent.cpp:636-679 client side; server.cpp:1185-1213 server side).
//
// SNI override, ALPN selection, and client-cert request mode are
// captured here so the gRPC adapter and msquic implementation carry
// equivalent surfaces; without them, a future lift-and-shift would
// silently drop protections.
//
// PEM material handling — IMPLEMENTATION CONTRACT:
//   * `client_key_pem` and `server_key_pem` MUST be passed through
//     `yuzu::secure_zero(...)` after the underlying TLS library has
//     consumed them. The Credentials destructor is NOT the right place
//     (consumption point is); copies returned from `reload()` are
//     consumed once and zeroed on the same path.
//   * `verify_peer = false` and `client_cert_mode = ClientCertMode::None`
//     in production builds MUST be refused — at startup AND on any
//     subsequent reload — unless the build was configured with
//     `YUZU_ALLOW_INSECURE_TLS=1` (mirroring the existing server-side
//     env gate at `server/core/src/insecure_tls_gate.hpp`). The env
//     gate is read once at process start; downstream the transport
//     enforces the same posture on every reload(). If the gate is off
//     and a reload returns insecure material, the reload FAILS as
//     `StatusCode::FailedPrecondition`; the existing Credentials remain
//     in force. The transport logs an audit event of category
//     `transport.insecure_tls_observed` whenever insecure material is
//     observed, regardless of whether the connection ultimately
//     proceeded.
//   * `reload` callback contract: invoked before each new connection
//     (client) or each new TLS handshake (server). If the callback
//     throws, the connection attempt FAILS with StatusCode::Unauthenticated.
//     If it returns a Credentials with empty PEM in any required field,
//     the connection FAILS. If the returned material fails cert-chain
//     validation against the configured CA, the connection FAILS.
//     There is NO fallback to the previously-loaded Credentials and NO
//     plaintext fallback. Reload-driven downgrades are rejected on a
//     partial-order basis (any change that strictly weakens
//     authentication posture relative to the live state fails as
//     `StatusCode::FailedPrecondition`):
//       - `verify_peer`: live=true → reload=false NOT permitted.
//       - `client_cert_mode`: ordinal Require > Request > None; a reload
//         that strictly weakens (Require → Request, Require → None,
//         Request → None) NOT permitted.
//       - `alpn_protocols`: a reload that DROPS a previously-required
//         protocol while keeping a weaker alternative (e.g. removing
//         `yuzu/1` from a set that also contained `h2`) NOT permitted.
//         Adding new protocols, or replacing the set with one of equal
//         or stronger posture, IS permitted.
//       - `sni_hostname`: change permitted (cosmetic, not security-
//         relevant for endpoint validation when CA pinning is in force).
//       - `cert_lifecycle_policy_url`: change permitted.
//     The PEM material itself (cert, key, CA bundle) may rotate freely
//     under reload; this contract regulates only the protocol-selector
//     fields above.
//   * `cert_lifecycle_policy_url` (when set) names a documented policy
//     for cert validity, revocation, and rotation cadence — required
//     before PR 3 merges per Workstream B. May be empty during
//     scaffolding; impl tests should still run.

enum class ClientCertMode {
    None,     // server does not request client certs (test builds only)
    Request,  // server requests but does not require client cert
    Require,  // server requests and requires; default
};

struct Credentials {
    std::string client_cert_pem;   // empty on server-side
    std::string client_key_pem;    // empty on server-side; consumer must secure_zero
    std::string ca_cert_pem;       // empty in plaintext mode
    std::string server_cert_pem;   // empty on client-side
    std::string server_key_pem;    // empty on client-side; consumer must secure_zero

    // SNI hostname override (empty = derive from Endpoint::host). Used
    // when the agent connects to a load-balanced address whose cert CN
    // is the canonical service name rather than the LB's address.
    std::string sni_hostname;

    // ALPN protocols offered/required at handshake. Default for the
    // QUIC backend is `{"yuzu/1"}` (a single Yuzu-specific identifier);
    // the gRPC backend ignores this and uses `h2`. A cross-backend
    // mismatch (gRPC client expects h2, msquic server only offers
    // yuzu/1) surfaces as StatusCode::Unavailable with a transport
    // metric `yuzu_transport_alpn_mismatch_total{kind=...}`.
    std::vector<std::string> alpn_protocols = { "yuzu/1" };

    // Client-cert request mode (server-side meaning).
    ClientCertMode client_cert_mode = ClientCertMode::Require;

    // Whether to verify the peer's cert chain against `ca_cert_pem`.
    // True is the only production-safe value. See contract above.
    bool verify_peer = true;

    // Connection-establishment timeout. Survives reconnect attempts.
    // Default = 30s, matching the existing gRPC reconnect-loop budget
    // in agent.cpp.
    std::chrono::milliseconds connect_timeout = std::chrono::seconds(30);

    // URL of the cert lifecycle policy this Credentials adheres to.
    // Empty = no policy declared. Used by audit emitters and Workstream B
    // evidence collection.
    std::string cert_lifecycle_policy_url;

    // Reload hook. If set, the transport calls this before each
    // connection (client) or each new TLS handshake (server) to obtain
    // freshly-loaded material. See contract above for failure modes.
    std::function<Credentials()> reload;
};

// =====================================================================
// CallContext
// =====================================================================
//
// CallContext travels with a single RPC invocation (client side) or a
// single dispatched call (server side).
//
// Initial vs trailing metadata: the `metadata` field carries INITIAL
// metadata only (the pre-RPC headers). Trailing metadata is delivered
// via CallResult::trailing_metadata after the call completes.
//
// Server-side fields (peer_uri, peer_san_identities) are populated by
// the transport when constructing a CallContext for a dispatched call;
// they are unused (empty) on the client side.
//
// Cancel propagation:
//
//   * Client side: callers pass their own stop_token via
//     `CallContext::cancel`. `cancel.stop_requested()` reliably aborts
//     the in-flight RPC across all backends — the gRPC backend
//     translates this to `gctx_.TryCancel()` via a stop_callback;
//     msquic will translate to its native stream-shutdown primitive.
//
//   * Server side: `cancel` is BACKEND-BEST-EFFORT and may NEVER fire
//     on the gRPC backend. The historical contract claimed the
//     transport managed a per-call stop_source whose token surfaced
//     peer disconnection; that wiring is not implemented on the gRPC
//     backend and is deferred (#916). Server handlers in this codebase
//     already detect peer disconnect via `read()` returning false on
//     the BidiStream (see `AgentServiceImpl::Subscribe` and
//     `AgentServiceImpl::DownloadUpdate`), which is reliable across
//     backends and the canonical pattern. Do NOT add new server-side
//     handlers that block on `cancel.stop_requested()` for peer-
//     disconnect detection — use `read()`-returns-false instead, or
//     add the gRPC AsyncNotifyWhenDone wiring under #916 first.
//
//     Rationale (2026-05-09 PR 1c-4 design grilling): every current
//     server handler is an event pump where `read()` is the natural
//     blocking primitive; promoting `cancel` to load-bearing would
//     require wiring AsyncNotifyWhenDone per call, which adds a CqTag
//     to a hot path that #904's bounded bidi dispatcher pool just
//     fought to keep cheap. Yuzu's submit-and-poll pattern keeps
//     long-running work agent-side; server handlers stay short and
//     `read()`-driven, so this contract softening is no production
//     functionality lost.
//
// Deadline = 0 (`std::chrono::milliseconds::zero()`) means "no
// deadline" — matches the proto's deadline_unix_millis = 0 semantics.
// To express "expire immediately", use deadline = milliseconds(1).
struct CallContext {
    std::chrono::milliseconds deadline = std::chrono::milliseconds::zero();
    std::map<std::string, std::string> metadata;
    std::stop_token cancel;

    // Server-side only: populated by the transport backend before handler
    // dispatch. Despite the field name, this is the canonical "verified
    // peer identities for authn" surface across backends — NOT just the
    // raw x509 SAN extension. The gRPC backend folds the union of
    // `GetPeerIdentity()` + `x509_common_name` + `x509_subject_alternative_name`
    // into the vector (deduplicated, first-wins); a future msquic backend
    // (PR 3) MUST satisfy the same authn contract by populating an
    // equivalent identity set so consumers like
    // `AgentServiceImpl::peer_identity_matches_agent_id` accept/reject the
    // same callers. Field rename to `peer_identities` is deferred to keep
    // the lift commit narrow; semantics are documented here.
    std::string peer_uri;
    std::vector<std::string> peer_san_identities;
};

// CallResult carries the trailing status of any completed call. For
// unary RPCs the response message is delivered separately; this only
// reports success/failure.
struct CallResult {
    Status status;
    std::map<std::string, std::string> trailing_metadata;
};

// =====================================================================
// SerializableMessage + ProtoMessage<T> adapter
// =====================================================================
//
// SerializableMessage is the minimal contract a stream message must
// satisfy. Implementations call serialize / parse on the underlying
// message via a small adapter; this header keeps protobuf headers out
// of the public surface.
//
// `parse()` failure semantics: returning false MUST be treated by the
// transport as fatal stream corruption — the impl cancels the stream
// with StatusCode::DataLoss and emits an audit event. It is NEVER
// "skip frame and continue reading" — that would create a frame
// injection vector on a length-prefixed stream.
//
// `serialize()` failure semantics: returning false aborts the call
// with StatusCode::Internal. Typical causes: arena exhaustion,
// oversized output (> the listener's configured max_frame_size), invariant violation in the
// underlying message. NEVER skip; never silently truncate.
class SerializableMessage {
public:
    virtual ~SerializableMessage() = default;
    virtual bool serialize(std::string& out) const = 0;
    virtual bool parse(std::string_view in) = 0;
};

// ProtoMessage<T> adapts any protobuf MessageLite-derived class T to
// the SerializableMessage interface. Defined in the companion header
// `yuzu/transport/proto_adapter.hpp` to keep <google/protobuf/message_lite.h>
// out of this header. Callers do:
//
//     pb::CommandRequest req;
//     yuzu::transport::ProtoMessage<pb::CommandRequest> req_adapter(req);
//     bidi->write(req_adapter);
//
// Or, more commonly, use the `as_proto(...)` free function in
// proto_adapter.hpp which infers T from the argument.
template <typename T>
class ProtoMessage;  // defined in transport/proto_adapter.hpp

// =====================================================================
// BidiStream
// =====================================================================
//
// BidiStream is the server-streaming, client-streaming, and bidi-streaming
// surface — the most general shape. The other two streaming kinds are
// degenerate cases (read or write half disabled).
//
// Half-close direction contract:
//   * After `read()` returns false (peer half-close), `write()` REMAINS
//     valid until `writes_done()` is called. Common server pattern:
//     read until peer half-closes, then write the final response, then
//     writes_done(). This mirrors gRPC half-close semantics; the
//     msquic implementation honours it via the TrailingStatus envelope.
//   * After local `writes_done()`, `read()` continues to drain
//     incoming frames until the peer half-closes.
//
// Threading contract:
//   * BidiStream is THREAD-COMPATIBLE (single-writer, single-reader).
//     Concurrent `write()` from multiple threads is undefined behaviour;
//     callers MUST serialise externally. Concurrent `read()` from
//     multiple threads is similarly UB.
//   * A read thread and a write thread MAY operate concurrently — that
//     is the point of bidi.
//   * `cancel()` is observable from any thread. After cancel(), any
//     subsequent or in-flight write/read returns false; the
//     synchronisation is sequentially consistent (cancel() happens-
//     before the false return).
//   * `final_status()` MUST be called from the reader thread (or after
//     it has finished). Calling final_status() from a third thread
//     while a reader is still draining is undefined.
//   * `cancel()` is idempotent; calling it after `final_status()` has
//     returned is a safe no-op.
//   * Deadline expiry on `read(msg, deadline)` OR `write(msg, deadline)`
//     is internally equivalent to `cancel()` from a third thread firing
//     exactly when the deadline lapses. Subsequent reads/writes return
//     false; only the `final_status()` reporting changes (DeadlineExceeded
//     vs Cancelled). This means deadline cancellation is observable on
//     both the reader and writer threads — a writer racing with a
//     reader's deadline expiry sees false from `write()` after the
//     deadline fires, and vice versa for reader vs writer deadline.
//
// Wire ordering contract (msquic backend):
//   * The sender emits frames in `write()` order, each with a 4-byte
//     big-endian length prefix.
//   * `writes_done()` flushes any buffered frames, then emits exactly
//     one TrailingStatus frame, then signals QUIC stream FIN.
//   * Receiving any frame after a TrailingStatus is corruption; the
//     stream is cancelled with StatusCode::DataLoss.
//   * The gRPC backend uses HTTP/2 trailers and does not emit
//     TrailingStatus on the wire.
class BidiStream {
public:
    virtual ~BidiStream() = default;

    // Write a frame. Blocks until the frame is accepted into the transport
    // buffer (NOT until it lands on the wire). Returns false if the stream
    // has been finished (`writes_done()` called) or cancelled.
    //
    // `deadline` is an optional per-call write timeout. Zero (the default)
    // mirrors `CallContext::deadline` semantics — wait indefinitely until
    // the transport accepts the frame or the stream is cancelled. A
    // positive value caps the wait at that duration; if the transport
    // does not accept the frame by then (a slow-write peer with a
    // collapsed receive window, NAT/firewall holding the stream, or
    // HTTP/2 flow-control window exhaustion), the stream is cancelled
    // (`gctx_.TryCancel()` on the gRPC backend; the analogous QUIC stream
    // close on a future msquic backend), the write returns false, and
    // `final_status()` reports `StatusCode::DeadlineExceeded`. Both
    // backends MUST honour this — the deadline is what bounds bidi
    // dispatcher pool slot residency for slow-write peers (#911 / UP-101)
    // and is symmetric with the read-side idle deadline (#902 / UP-8).
    //
    // The deadline applies ONLY to this specific write call, not to the
    // stream as a whole. A handler streaming N chunks may arm the same
    // (or different) deadline on each frame; total stream lifetime is
    // bounded by N × deadline rather than the per-frame value alone.
    //
    // **Negative deadlines are treated as zero** (no deadline / unbounded
    // wait), symmetric with the read-side semantics. To express "expire
    // immediately", pass `milliseconds(1)`.
    virtual bool write(const SerializableMessage& msg,
                       std::chrono::milliseconds deadline =
                           std::chrono::milliseconds::zero()) = 0;

    // Read the next frame into msg. Returns true on success, false on
    // half-close from the peer, on cancellation, or on idle-read deadline
    // expiry. Use `final_status()` after a false return to learn why.
    //
    // `deadline` is an optional per-call idle timeout. Zero (the default)
    // mirrors `CallContext::deadline` semantics — wait indefinitely until
    // peer half-close or cancellation. A positive value caps the wait at
    // that duration; if no frame arrives by then, the stream is cancelled
    // (`gctx_.TryCancel()` on the gRPC backend; the analogous QUIC stream
    // close on a future msquic backend), the read returns false, and
    // `final_status()` reports `StatusCode::DeadlineExceeded` on both
    // sides. Both backends MUST honour this — the deadline is what
    // bounds the bidi dispatcher pool slot residency for misbehaving
    // peers (#902 / UP-8).
    //
    // **Negative deadlines are treated as zero** (no deadline / unbounded
    // wait), matching the `CallContext::deadline = zero()` convention
    // already in this header. This is defensive against caller patterns
    // like `deadline = max(0ms, target_deadline - now())` where a missed
    // target would otherwise underflow into a negative value; without
    // the clamp the caller would pin the stream forever instead of
    // expiring promptly. To express "expire immediately", pass
    // `milliseconds(1)` (closes #915 / UP-110 / arch-S1).
    //
    // The deadline applies ONLY to this specific read call, not to the
    // stream as a whole. A handler may call `read()` repeatedly with
    // different deadlines (or the same one) to enforce per-frame idle
    // policies. For example, a typical "client streams one request,
    // server streams N responses" pattern caps just the first read
    // (waiting for the request frame); subsequent server-side reads
    // are short or use the default unbounded form because the peer is
    // expected to half-close quickly.
    //
    // Server-side: deadline expiry surfaces to the handler as `read()`
    // returning false; the handler should treat it like any other false
    // return (the transport has already cancelled the stream). The
    // handler MAY call `final_status()` on its own stream to learn that
    // the false return was specifically deadline expiry (returns
    // `DeadlineExceeded`) versus peer half-close or external cancel
    // (returns `Ok`). Note: the wire-level trailing status the peer
    // observes after a server-side deadline cancellation is
    // `Cancelled` on the gRPC backend (gRPC's `TryCancel` sends
    // RST_STREAM before `Finish` runs, and the supplied final status
    // is overridden by that early cancel). Cross-side propagation of
    // "the other side timed out" is therefore best-effort — it
    // happens reliably for client-side deadlines (the client's own
    // `final_status()` returns `DeadlineExceeded` from the local
    // flag) but not for server-side ones. A future msquic backend MAY
    // honour the handler-supplied final status more faithfully via
    // its TrailingStatus frame.
    virtual bool read(SerializableMessage& msg,
                      std::chrono::milliseconds deadline =
                          std::chrono::milliseconds::zero()) = 0;

    // Half-close the writer side (no more outgoing frames). Reader side
    // continues to drain incoming frames until the peer half-closes.
    virtual void writes_done() = 0;

    // Final status of the stream after both halves have closed. Blocks
    // until the trailing-status frame has been received from the peer.
    // MUST be called from the reader thread (or after it has finished).
    //
    // If `read()` returned false because its idle-read deadline expired,
    // `final_status()` returns `StatusCode::DeadlineExceeded` regardless
    // of whether the wire-level trailing status would otherwise have
    // been Cancelled (because the deadline path cancels the stream
    // internally). This makes "deadline vs cancel vs peer-close"
    // distinguishable on both sides.
    virtual Status final_status() = 0;

    // Trailing metadata, available after final_status() returns.
    virtual const std::map<std::string, std::string>& trailing_metadata() const = 0;

    // Cancel the stream. Both reads and writes return false thereafter.
    // Idempotent; safe to call multiple times and after final_status().
    virtual void cancel() = 0;
};

// =====================================================================
// Observability: TransportMetricSink
// =====================================================================
//
// Every Channel/ServerListener accepts an optional metric sink so both
// backends report identically into the same Prometheus surface. The
// existing gRPC code emits metrics under `yuzu_server_transport_*` and
// `yuzu_agent_transport_*`; the sink centralises that wiring.
//
// All callbacks MUST be safe to invoke from any internal transport
// thread. Implementations of TransportMetricSink should be lock-free
// or rely on prometheus-cpp counters (which are lock-free).
struct TransportMetricSink {
    virtual ~TransportMetricSink() = default;

    virtual void on_connection_opened(std::string_view backend) {}
    virtual void on_connection_closed(std::string_view backend, Status final) {}

    virtual void on_stream_opened(std::string_view backend, std::string_view method) {}
    virtual void on_stream_closed(std::string_view backend, std::string_view method,
                                  Status final) {}

    virtual void on_bytes_sent(std::string_view backend, std::size_t bytes) {}
    virtual void on_bytes_received(std::string_view backend, std::size_t bytes) {}

    // One-way frame latency, available on QUIC backend (via ACK events);
    // gRPC backend leaves this as a no-op.
    virtual void on_frame_delivered(std::string_view backend,
                                    std::chrono::nanoseconds one_way) {}

    // ALPN negotiation outcome. Called once per connection at handshake.
    virtual void on_alpn_negotiated(std::string_view backend,
                                    std::string_view negotiated_protocol) {}

    // The dispatcher's per-event try/catch fires this callback when a
    // throw escapes a handler invocation OR a transport-internal
    // dispatch step (governance UP-42 / UP-57 / SRE-O1). `kind` is one
    // of {"std_exception", "non_std_exception", "dispatcher_internal"}
    // — cardinality is bounded so it is safe as a Prometheus label.
    //
    // `method` is either empty (throw originated before method
    // resolution, e.g. dispatcher_internal) OR a method name that has
    // already been confirmed registered against the listener's handler
    // map (i.e., chosen by the operator at startup). It is therefore
    // bounded-cardinality from the operator-controlled set, NOT
    // attacker-controlled. Implementations of this sink MAY label a
    // Prometheus counter by `method` directly without bucketing.
    // Implementations MUST NOT pass `e.what()` text through this
    // surface (governance round 5 re-review M3 + M2).
    //
    // The callback MUST NOT throw.
    virtual void on_unexpected_dispatch_throw(std::string_view backend,
                                              std::string_view method,
                                              std::string_view kind) {}

    // Bidi dispatcher pool observability (#912 / CMP-2 / OBS-1 / UP-111).
    //
    // The bounded bidi pool (#904) caps concurrency, but operators need
    // alertable signals to distinguish "pool full → resize" from
    // "internal failure → investigate" and to graph in-flight residency
    // versus configured cap.
    //
    // `on_bidi_pool_size` fires once at listener start with the resolved
    // pool cap, and again on shutdown with size = 0. Implementations
    // typically expose this as a gauge.
    //
    // `on_bidi_pool_in_flight_delta(+1)` fires on enqueue (call accepted
    // into the pool); `on_bidi_pool_in_flight_delta(-1)` fires on
    // dequeue (worker picked the call up and is about to run the
    // handler). Implementations typically expose the running sum as a
    // gauge. Note: the residency gauge measures queue depth, not
    // concurrent handler count — a worker running a long-lived bidi
    // handler holds 0 in-flight units.
    //
    // `on_bidi_pool_saturated` fires on the saturation reject path —
    // `bidi_dispatcher_pool_size` calls are already enqueued and a new
    // call cannot be accepted. The peer sees `ResourceExhausted`.
    // `method` is the bounded-cardinality method name (same contract as
    // `on_unexpected_dispatch_throw`).
    //
    // All three callbacks MUST NOT throw.
    virtual void on_bidi_pool_size(std::string_view backend,
                                   std::uint32_t size) {}
    virtual void on_bidi_pool_in_flight_delta(std::string_view backend,
                                              int delta) {}
    virtual void on_bidi_pool_saturated(std::string_view backend,
                                        std::string_view method) {}
};

// =====================================================================
// BackoffPolicy
// =====================================================================
//
// Reconnect backoff parameters threaded through `make_channel`. The
// transport layer enforces jittered exponential backoff so a fleet-wide
// transient failure does not synchronise into a thundering herd. Defaults
// match the existing gRPC reconnect-loop budget.
struct BackoffPolicy {
    std::chrono::milliseconds initial_delay  = std::chrono::milliseconds(500);
    std::chrono::milliseconds max_delay      = std::chrono::seconds(30);
    double multiplier                         = 1.6;
    double jitter_fraction                    = 0.2;  // ±20%
};

// =====================================================================
// ListenerOptions
// =====================================================================
//
// Server-side capacity controls. Zero means "use backend default".
struct ListenerOptions {
    // Max concurrent streams per connection (gRPC: GRPC_ARG_MAX_CONCURRENT_STREAMS;
    // msquic: QUIC_PARAM_CONN_SETTINGS.PeerBidiStreamCount).
    uint32_t max_concurrent_streams_per_connection = 0;

    // Hard cap on connection count; zero = unbounded.
    uint32_t max_connections = 0;

    // Bounded thread pool that runs bidi handlers (governance UP-14, #904).
    //
    // Pre-#904 the dispatcher spawned one std::thread per active bidi RPC.
    // At fleet scale (10K agent Subscribes × 8 MiB Linux default stack ≈
    // 80 GiB virtual address space) the implicit fanout exhausted thread
    // creation budgets and head-of-line-blocked the cq_worker on
    // handler_thread_.join() (UP-13). Implementations MUST cap the
    // dispatcher's concurrent thread count at this value.
    //
    // ── Saturation rejection contract (cross-backend) ────────────────────
    // When in-flight handler count == pool size, new submissions MUST be
    // REJECTED (not queued) by emitting:
    //   * Status::code == StatusCode::ResourceExhausted, AND
    //   * Status::detail exactly equal to the string literal
    //     "transport: bidi dispatcher saturated".
    // The exact-string mandate is load-bearing: operator dashboards and
    // alert rules key on the literal text to distinguish capacity events
    // from internal-throw failures (which use the distinct
    // "transport: bidi dispatcher unavailable" detail). Both backends
    // (gRPC today, msquic in #376 PR 3) MUST honour the literal text.
    //
    // ── Per-listener scope ───────────────────────────────────────────────
    // This field configures THIS listener's pool only — it is NOT a
    // process-wide setting. A server hosting multiple ServerListeners
    // (eg. one for the agent-facing port and one for the management port)
    // sets this independently per listener. Today only the agent-facing
    // listener is on transport::ServerListener (#376 PR 1c-2); the
    // management plane lifts in PR 1c-5, at which point operators MAY
    // need a second knob if mgmt-plane bidi traffic appears.
    //
    // ── Drain ordering (cross-backend) ───────────────────────────────────
    // Implementations MUST drain the bidi handler pool only AFTER the
    // frame reader (cq_worker on gRPC; the analogous QUIC frame loop on
    // msquic) has exited, so handlers parked on backend-internal
    // condition variables observe completion events before the pool joins
    // its workers. Reversing this order risks shutdown deadlock.
    //
    // Sizing guidance:
    //   * Zero => backend picks a sensible default (gRPC: clamp(64,
    //     hardware_concurrency * 8, 4096), with hardware_concurrency==0
    //     treated as 4 to keep the floor at 64 in containers; msquic:
    //     SHOULD match — see #376 PR 3 implementation comment).
    //   * Operators with steady-state >N concurrent bidi streams (eg.
    //     long-lived Subscribes per fleet agent on direct-connect
    //     deployments) MUST set this >= expected steady-state count, or
    //     route through the gateway (which terminates Subscribe so the
    //     server only sees per-gateway concurrency).
    //   * In-flight handler count ≤ pool size; new submissions when the
    //     pool is saturated are REJECTED, not queued. This is intentional
    //     backpressure: a saturated server fails fast so callers retry
    //     elsewhere rather than amassing OS threads to exhaustion.
    //
    // Bidi-only: unary handlers run on the cq_worker thread (or backend
    // equivalent) and are NOT gated by this pool — they are CPU-bound,
    // run-to-completion, and the frame reader drains them serially per
    // the AsyncGenericService model.
    uint32_t bidi_dispatcher_pool_size = 0;

    // Maximum size of a single framed protobuf message accepted on
    // this listener. Zero means use kDefaultMaxFrameSize (4 MiB,
    // matching gRPC default). Implementations MUST refuse values
    // greater than kAbsoluteMaxFrameSize (64 MiB). Operators with
    // legitimate large-frame use cases (e.g. fleet-wide inventory
    // aggregation) raise this explicitly; the explicit raise is
    // operator-visible (logged at startup, exposed via metrics).
    std::size_t max_frame_size = 0;

    // Optional metric sink (shared with consumers).
    std::shared_ptr<TransportMetricSink> metric_sink;
};

// =====================================================================
// Client-side
// =====================================================================

class Channel {
public:
    virtual ~Channel() = default;

    // Synchronous unary call. The request and response messages are
    // serialized/deserialized by the caller's adapter; the transport
    // sees them only as SerializableMessage.
    virtual CallResult unary(std::string_view method, const CallContext& ctx,
                             const SerializableMessage& request,
                             SerializableMessage& response) = 0;

    // Open a bidi stream. The returned object owns the underlying
    // transport state; destroying it cancels the stream if not finished.
    virtual std::unique_ptr<BidiStream> bidi_stream(std::string_view method,
                                                    const CallContext& ctx) = 0;

    // Wait until the channel is connected to the remote endpoint, or
    // the deadline elapses. Returns true on success.
    //
    // "Connected" means: the transport-level handshake (TLS 1.3 +
    // QUIC connection establishment, or HTTP/2 SETTINGS exchange) is
    // complete and the connection is ready to accept new streams.
    // It does NOT guarantee any particular server-side handler is
    // registered or that the application has reached steady-state.
    virtual bool wait_for_connected(std::chrono::milliseconds deadline) = 0;

    // Close the channel. In-flight calls are cancelled. Idempotent;
    // safe to call multiple times.
    virtual void close() = 0;
};

// =====================================================================
// Server-side
// =====================================================================
//
// Handlers are registered against a method name in the form
// "yuzu.<package>.<service>/<Method>". The same string the client passes
// to Channel::unary or Channel::bidi_stream.
//
// Method name validation: a method registered with a string that fails
// the HandshakeHello.method validation regex (see transport.proto) is
// rejected at register_* time with StatusCode::InvalidArgument. Dispatch
// at runtime is exact byte match.

using UnaryHandler =
    std::function<Status(const CallContext& ctx,
                         const SerializableMessage& request,
                         SerializableMessage& response)>;

using BidiStreamHandler =
    std::function<Status(const CallContext& ctx, BidiStream& stream)>;

class ServerListener {
public:
    virtual ~ServerListener() = default;

    // Register a handler for a unary RPC. The factory functions create
    // fresh request/response message instances per call.
    virtual void register_unary(
        std::string method,
        std::function<std::unique_ptr<SerializableMessage>()> request_factory,
        std::function<std::unique_ptr<SerializableMessage>()> response_factory,
        UnaryHandler handler) = 0;

    // Register a handler for a bidi-streaming RPC.
    virtual void register_bidi_stream(std::string method,
                                      BidiStreamHandler handler) = 0;

    // Bind to the given endpoint and start serving. After this call,
    // register_* calls fail with StatusCode::FailedPrecondition.
    //
    // Requests dispatched to an unregistered method name receive a
    // trailing StatusCode::Unimplemented response.
    virtual std::expected<void, Status> start(const Endpoint& bind,
                                              const Credentials& creds,
                                              const ListenerOptions& opts = {}) = 0;

    // Block until shutdown() is called. Used by the main thread of
    // server processes.
    virtual void wait_for_shutdown() = 0;

    // Initiate graceful shutdown. In-flight handlers run to completion;
    // new connections are refused. wait_for_shutdown() returns once the
    // last handler exits.
    //
    // Shutdown trailing-status guarantee: all active server-streaming
    // and bidi-streaming handlers receive StatusCode::Unavailable as
    // the trailing status delivered to clients. This distinguishes a
    // server restart from an application-level cancellation, so agents
    // reconnect immediately rather than respecting their own cancel
    // path's backoff.
    virtual void shutdown() = 0;

    // Health surface used by /readyz and equivalent: returns true iff
    // the listener has called start() successfully and shutdown() has
    // not been called. Required for the dual-stack readiness probe
    // conjunction in PR 5+.
    virtual bool is_serving() const noexcept = 0;

    // Returns the actual address the listener is bound to. After a
    // successful start(), `port` is the OS-assigned port if the
    // caller passed `bind.port = 0` for ephemeral allocation.
    // Returns `{"", 0}` if start() has not succeeded.
    //
    // Use this to discover the bound port for tests and any caller
    // that asked for ephemeral allocation. The returned value is
    // stable across the lifetime of the listener so callers may cache
    // it — but they MUST gate any "is this address live?" decision on
    // is_serving(): after shutdown(), bound_endpoint() continues to
    // return the last successfully-bound address (the field is not
    // cleared), and a stale endpoint paired with a dead listener is
    // exactly the false-green readiness pattern this contract aims to
    // prevent (governance UP-40 / SRE-O2). The conjunction
    // `is_serving() && bound_endpoint().port != 0` is the readiness
    // signal; either half alone is insufficient.
    //
    // WILDCARD-host caveat. When `bind.host` is a wildcard literal
    // (`"0.0.0.0"`, `"::"`, empty), bound_endpoint().host echoes the
    // wildcard verbatim. Callers MUST NOT broadcast a wildcard host
    // to peers in any federation, discovery, or health-share path —
    // resolve to a routable interface address first (governance UP-56).
    virtual Endpoint bound_endpoint() const noexcept = 0;
};

// =====================================================================
// Factories
// =====================================================================
//
// Two implementations live in transport/src/. Selection at runtime is
// via the build-time toggle `-Dtransport=grpc|msquic|both` plus the
// runtime `--transport=grpc|quic|auto` flag (added in PR 5).
//
// Build-time selection is enforced by linking the matching backend lib;
// runtime selection picks among the linked-in factories. After PR 8
// (gRPC removal), Backend::Grpc is deleted and the dual-axis selection
// collapses to msquic-only.

enum class Backend {
    Grpc,
    Msquic,
};

// Construct a client-side channel. Returns nullptr if the requested
// backend is not linked in. Both metric_sink and backoff are optional;
// pass {} for defaults.
std::unique_ptr<Channel> make_channel(Backend backend,
                                      const Endpoint& target,
                                      const Credentials& creds,
                                      BackoffPolicy backoff = {},
                                      std::shared_ptr<TransportMetricSink> metric_sink = {});

// Construct a server-side listener.
std::unique_ptr<ServerListener> make_server_listener(Backend backend);

// String <-> Backend conversion (used by --transport flag parsing).
std::string_view backend_name(Backend b) noexcept;
std::expected<Backend, Status> parse_backend(std::string_view name) noexcept;

}  // namespace yuzu::transport
