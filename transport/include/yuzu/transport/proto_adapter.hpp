// SPDX-License-Identifier: Apache-2.0
// yuzu::transport::ProtoMessage<T> — bridge between protobuf MessageLite
// types and the SerializableMessage interface in transport.hpp.
//
// Kept in a separate header so transport.hpp itself does not pull in
// <google/protobuf/message_lite.h>; consumers that don't need to call
// Channel::unary / BidiStream::write/read directly avoid the protobuf
// header transitively.
//
// Usage:
//
//     pb::CommandRequest req;
//     pb::CommandResponse resp;
//     yuzu::transport::CallContext ctx;
//     auto result = channel->unary(
//         "yuzu.agent.v1.AgentService/ExecuteCommand",
//         ctx,
//         yuzu::transport::as_proto(req),
//         yuzu::transport::as_proto(resp));
//
// The `as_proto(...)` helper deduces T and returns a non-owning
// SerializableMessage adapter over the caller-owned message.

#pragma once

#include <google/protobuf/message_lite.h>

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "yuzu/transport/transport.hpp"

namespace yuzu::transport {

// Adapter wrapping any protobuf MessageLite-derived type. The wrapped
// reference must outlive the adapter.
template <typename T>
class ProtoMessage final : public SerializableMessage {
    static_assert(std::is_base_of_v<google::protobuf::MessageLite, T>,
                  "ProtoMessage<T> requires T derives from google::protobuf::MessageLite");

public:
    explicit ProtoMessage(T& msg) noexcept : msg_(msg) {}

    bool serialize(std::string& out) const override {
        out.clear();
        // SerializeToString returns false on unset required fields or
        // serialisation overflow. Callers in transport.hpp treat false
        // as fatal-stream-abort with StatusCode::Internal.
        return msg_.SerializeToString(&out);
    }

    bool parse(std::string_view in) override {
        // ParseFromArray returns false on wire-corrupt input. Callers
        // in transport.hpp treat false as fatal-stream-corruption with
        // StatusCode::DataLoss.
        return msg_.ParseFromArray(in.data(), static_cast<int>(in.size()));
    }

private:
    T& msg_;
};

// as_proto deduces T and returns a stack-allocatable adapter. Callers
// pass by reference into Channel::unary / BidiStream::write etc.
template <typename T>
ProtoMessage<T> as_proto(T& msg) noexcept {
    return ProtoMessage<T>(msg);
}

template <typename T>
ProtoMessage<T> as_proto(const T& msg) noexcept {
    // const_cast is safe because SerializableMessage::serialize is const
    // and only read-accesses the message; SerializableMessage::parse is
    // non-const but is never called via this overload (the caller's
    // const-correctness expresses "I am writing this on the wire").
    return ProtoMessage<T>(const_cast<T&>(msg));
}

// =====================================================================
// OwnedProtoMessage<T> — owning variant of ProtoMessage<T>.
// =====================================================================
//
// `ProtoMessage<T>` wraps a caller-owned T by reference, which is what
// the client side wants (the caller already has a `pb::HeartbeatRequest`
// on the stack). The server-side dispatch path needs the opposite shape:
// the listener calls a `request_factory()` that yields a fresh
// `unique_ptr<SerializableMessage>` ready to be filled by `parse(bytes)`,
// then hands that message to the handler.
//
// `OwnedProtoMessage<T>` owns a default-constructed T inside the adapter.
// The factory function returns `std::make_unique<OwnedProtoMessage<T>>()`
// and the handler reaches into the typed message via `.value()`.
template <typename T>
class OwnedProtoMessage final : public SerializableMessage {
    static_assert(std::is_base_of_v<google::protobuf::MessageLite, T>,
                  "OwnedProtoMessage<T> requires T derives from "
                  "google::protobuf::MessageLite");
    static_assert(std::is_default_constructible_v<T>,
                  "OwnedProtoMessage<T> requires T be default-constructible "
                  "(generated proto types satisfy this)");

public:
    OwnedProtoMessage()                                   = default;
    OwnedProtoMessage(const OwnedProtoMessage&)           = delete;
    OwnedProtoMessage& operator=(const OwnedProtoMessage&) = delete;

    bool serialize(std::string& out) const override {
        out.clear();
        return msg_.SerializeToString(&out);
    }

    bool parse(std::string_view in) override {
        return msg_.ParseFromArray(in.data(), static_cast<int>(in.size()));
    }

    T&       value() noexcept       { return msg_; }
    const T& value() const noexcept { return msg_; }

private:
    T msg_;
};

// Factory returning std::unique_ptr<SerializableMessage> backed by a
// fresh OwnedProtoMessage<T>. Suitable for ServerListener::register_unary
// `request_factory` / `response_factory` arguments.
template <typename T>
std::function<std::unique_ptr<SerializableMessage>()> proto_factory() {
    return [] { return std::make_unique<OwnedProtoMessage<T>>(); };
}

// =====================================================================
// register_unary_pb<Req, Resp> — typed unary registration helper.
// =====================================================================
//
// Wraps `ServerListener::register_unary` so handlers see fully-typed
// proto messages instead of `SerializableMessage&`. Without this helper,
// every registration site has to write the same five lines of
// downcast-from-SerializableMessage / construct-OwnedProtoMessage
// boilerplate; with it, the call site reads as one statement plus a
// lambda body.
//
//     register_unary_pb<pb::HeartbeatRequest, pb::HeartbeatResponse>(
//         *listener,
//         "yuzu.agent.v1.AgentService/Heartbeat",
//         [&](const CallContext& ctx, const pb::HeartbeatRequest& req,
//             pb::HeartbeatResponse& resp) -> Status {
//             // ... typed handler body ...
//             return Status{StatusCode::Ok, ""};
//         });
//
// The factories produce OwnedProtoMessage<T> instances; the wrapper
// lambda static_casts down to retrieve the typed value(). Behaviour on
// unrelated downcast (which the listener cannot produce because it owns
// the factories) is undefined.
template <typename Req, typename Resp, typename Fn>
void register_unary_pb(ServerListener& listener, std::string method,
                       Fn handler) {
    static_assert(
        std::is_invocable_r_v<Status, Fn, const CallContext&, const Req&, Resp&>,
        "register_unary_pb<Req, Resp>(handler): handler must be callable "
        "with signature Status(const CallContext&, const Req&, Resp&)");

    listener.register_unary(
        std::move(method), proto_factory<Req>(), proto_factory<Resp>(),
        [h = std::move(handler)](const CallContext& ctx,
                                 const SerializableMessage& req,
                                 SerializableMessage& resp) -> Status {
            const auto& typed_req =
                static_cast<const OwnedProtoMessage<Req>&>(req);
            auto& typed_resp = static_cast<OwnedProtoMessage<Resp>&>(resp);
            return h(ctx, typed_req.value(), typed_resp.value());
        });
}

// =====================================================================
// bidi typed read/write helpers.
// =====================================================================
//
// Bidi handlers see `BidiStream&` directly; they exchange typed protos
// frame by frame. These helpers wrap the `as_proto(...)` + read/write
// pair into one call so handler bodies stay symmetric with
// register_unary_pb.

// Read a typed proto from the stream into `out`. Returns false on
// half-close, parse failure, cancel, or idle-read deadline expiry —
// same contract as `BidiStream::read` (transport.hpp).
//
// `deadline` defaults to zero (wait indefinitely). A positive value
// caps the per-call wait; on expiry the stream is cancelled and
// `BidiStream::final_status()` reports `DeadlineExceeded`. See the
// BidiStream contract block in transport.hpp for the full semantics.
//
// `[[nodiscard]]`: the bool return distinguishes peer half-close from
// frame-arrived; silently dropping it is almost always a bug. Callers
// that intentionally want fire-and-forget MUST use `(void)read_pb(...)`
// to express intent.
template <typename T>
[[nodiscard]] bool read_pb(BidiStream& stream, T& out,
                           std::chrono::milliseconds deadline =
                               std::chrono::milliseconds::zero()) {
    ProtoMessage<T> wrap(out);
    return stream.read(wrap, deadline);
}

// Write a typed proto to the stream. Returns false on cancel /
// already-finished / serialise overflow — same contract as
// `BidiStream::write`.
//
// `[[nodiscard]]`: a false return signals the stream is dead; further
// writes will also fail and the caller usually wants to bail. Sites
// that intentionally fire-and-forget (e.g. the agent's command-output
// pump where a dead stream is detected by the next read iteration)
// MUST use `(void)write_pb(...)` to express intent.
template <typename T>
[[nodiscard]] bool write_pb(BidiStream& stream, const T& msg) {
    auto wrap = as_proto(msg);  // overload const-casts internally; safe for serialize-only
    return stream.write(wrap);
}

}  // namespace yuzu::transport
