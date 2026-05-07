// SPDX-License-Identifier: Apache-2.0
// Internal helpers shared between the gRPC client and server backends.
// Single source of truth for: method-name validation regex, ByteBuffer
// <-> std::string conversion. Keeping these here avoids drift between
// grpc_channel.cpp and grpc_listener.cpp (governance round 4 cons-F2).

#pragma once

#include <grpcpp/support/byte_buffer.h>
#include <grpcpp/support/slice.h>

#include <regex>
#include <string>
#include <string_view>
#include <vector>

#include "yuzu/transport/transport.hpp"

namespace yuzu::transport::grpc_backend {

// Method-name validator matching the proto contract — see
// proto/yuzu/transport/framing/v1/transport.proto, HandshakeHello.method.
// Anchored so partial matches are rejected. Uses const char* pointer-pair
// regex_match for MSVC <regex> portability across the supported matrix.
inline bool method_name_well_formed(std::string_view method) noexcept {
    if (method.empty() || method.size() > kMaxMethodSize) return false;
    static const std::regex re{
        R"(^[A-Za-z][A-Za-z0-9_.]*\/[A-Za-z][A-Za-z0-9_]*$)"};
    return std::regex_match(method.data(), method.data() + method.size(), re);
}

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

// Sanitise a Status::detail string before it crosses the wire. Per the
// Status::detail visibility contract in transport.hpp:
//   * truncate at 1024 bytes
//   * replace non-printable / non-ASCII bytes with '?'
//   * NUL bytes specifically would be silently mangled by gRPC's
//     trailer encoding; replace them defensively (governance UP-22)
inline std::string sanitise_status_detail(std::string_view in) {
    constexpr std::size_t kMax = 1024;
    std::string out;
    const std::size_t n = std::min(in.size(), kMax);
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        const auto c = static_cast<unsigned char>(in[i]);
        if (c < 0x20 || c >= 0x7F) {
            out.push_back('?');
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    if (in.size() > kMax) out.append("...[truncated]");
    return out;
}

}  // namespace yuzu::transport::grpc_backend
