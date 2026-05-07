// SPDX-License-Identifier: Apache-2.0
// Method-name validator shared by GrpcChannel (client side) and
// GrpcServerListener (server side). Single source of truth for the
// proto contract regex documented in
// proto/yuzu/transport/framing/v1/transport.proto:113.
//
// MSVC `<regex>` has historically had issues with the iterator
// overloads of std::regex_match when called with std::string_view's
// char-pointer iterators in some /std:c++latest configurations. The
// const char* pointer-pair overload works on every supported
// compiler (GCC 13+, Clang 18+, MSVC 19.38+, Apple Clang 15+).

#pragma once

#include <regex>
#include <string_view>

#include "yuzu/transport/transport.hpp"

namespace yuzu::transport::grpc_backend {

inline bool method_name_well_formed(std::string_view method) noexcept {
    if (method.empty() || method.size() > kMaxMethodSize) return false;
    static const std::regex re{
        R"(^[A-Za-z][A-Za-z0-9_.]*\/[A-Za-z][A-Za-z0-9_]*$)"};
    return std::regex_match(method.data(), method.data() + method.size(), re);
}

}  // namespace yuzu::transport::grpc_backend
