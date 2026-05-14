// SPDX-License-Identifier: Apache-2.0
// Backend-neutral RPC method-name validator.
//
// Moved here from grpc_internal_helpers.hpp in #376 PR 3 so the msquic
// backend validates HandshakeHello.method with byte-identical semantics
// — the regex is a wire contract, not a gRPC implementation detail.
// Both backends re-export this into their own namespace.

#pragma once

#include <regex>
#include <string_view>

#include "yuzu/transport/transport.hpp"  // kMaxMethodSize

namespace yuzu::transport::detail {

// Method-name validator matching the proto contract — see
// proto/yuzu/transport/framing/v1/transport.proto, HandshakeHello.method.
// Anchored so partial matches are rejected. Uses const char* pointer-pair
// regex_match for MSVC <regex> portability across the supported matrix.
//
// An optional leading `/` is tolerated because gRPC's HTTP/2 `:path`
// header carries the slash for spec-conformant clients (the Erlang
// gateway via grpcbox, codegen-built gRPC stubs, curl-based testers),
// and that wire form surfaces through `gctx.method()` on the server
// dispatcher. The yuzu Channel historically passes the no-slash form;
// both spellings validate equally and the listener dispatch strips the
// optional `/` before handler lookup. The msquic backend's
// HandshakeHello path applies the same rule.
inline bool method_name_well_formed(std::string_view method) noexcept {
    if (method.empty() || method.size() > kMaxMethodSize) return false;
    static const std::regex re{
        R"(^/?[A-Za-z][A-Za-z0-9_.]*\/[A-Za-z][A-Za-z0-9_]*$)"};
    return std::regex_match(method.data(), method.data() + method.size(), re);
}

}  // namespace yuzu::transport::detail
