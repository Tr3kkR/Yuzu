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

#include <string>
#include <string_view>

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

}  // namespace yuzu::transport
