// SPDX-License-Identifier: Apache-2.0
// Internal helpers shared between the gRPC client and server backends.
// Single source of truth for: method-name validation regex, ByteBuffer
// <-> std::string conversion. Keeping these here avoids drift between
// grpc_channel.cpp and grpc_listener.cpp (governance round 4 cons-F2).

#pragma once

#include <grpcpp/support/byte_buffer.h>
#include <grpcpp/support/slice.h>

#include <string>
#include <string_view>
#include <vector>

#include "yuzu/transport/detail/method_name.hpp"  // method_name_well_formed
#include "yuzu/transport/detail/sanitise.hpp"     // sanitise_status_detail
#include "yuzu/transport/transport.hpp"

namespace yuzu::transport::grpc_backend {

// Re-export the cross-backend Status::detail sanitiser and method-name
// validator into the gRPC backend's namespace so existing call sites
// (`sanitise_status_detail(s)`, `method_name_well_formed(m)`) continue to
// resolve. The implementations live under
// `transport/include/yuzu/transport/detail/` so the msquic backend uses
// byte-identical semantics.
using ::yuzu::transport::sanitise_status_detail;
using ::yuzu::transport::detail::method_name_well_formed;

// Convert std::string bytes to grpc::ByteBuffer (single slice).
inline ::grpc::ByteBuffer string_to_byte_buffer(const std::string& bytes) {
    ::grpc::Slice slice(bytes.data(), bytes.size());
    return ::grpc::ByteBuffer(&slice, 1);
}

// Drain a grpc::ByteBuffer's slices into a flat std::string. Returns
// false if Dump fails (e.g., on a corrupted buffer); the transport
// layer treats false as DataLoss per the SerializableMessage contract.
inline bool byte_buffer_to_string(const ::grpc::ByteBuffer& buf,
                                  std::string& out) {
    std::vector<::grpc::Slice> slices;
    if (!buf.Dump(&slices).ok()) return false;
    out.clear();
    std::size_t total = 0;
    for (const auto& s : slices) total += s.size();
    out.reserve(total);
    for (const auto& s : slices) {
        out.append(reinterpret_cast<const char*>(s.begin()), s.size());
    }
    return true;
}

}  // namespace yuzu::transport::grpc_backend
