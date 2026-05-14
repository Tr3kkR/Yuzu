// SPDX-License-Identifier: Apache-2.0
// Shared test fixtures for the yuzu::transport test suites.
//
// `StringMessage` was previously defined verbatim in both
// test_transport_smoke.cpp and test_msquic_roundtrip.cpp; hoisted here so
// the increment-3+ bidi tests do not add a third copy (governance qe-S3
// / cons-N1).

#pragma once

#include <string>
#include <string_view>
#include <utility>

#include "yuzu/transport/transport.hpp"

namespace yuzu::transport::test {

// Minimal SerializableMessage carrying an opaque byte string — used by
// client (request/response) and server (handler) sides of round-trip
// tests across both transport backends.
class StringMessage final : public SerializableMessage {
public:
    StringMessage() = default;
    explicit StringMessage(std::string s) : data_(std::move(s)) {}

    bool serialize(std::string& out) const override {
        out = data_;
        return true;
    }
    bool parse(std::string_view in) override {
        data_.assign(in.data(), in.size());
        return true;
    }

    const std::string& data() const noexcept { return data_; }
    void set_data(std::string s) { data_ = std::move(s); }

private:
    std::string data_;
};

} // namespace yuzu::transport::test
