// SPDX-License-Identifier: Apache-2.0
// #376 PR 3 — msquic backend round-trip integration tests.
//
// These exercise the real msquic transport end to end: a server listener
// and a client channel, both over QUIC/TLS 1.3, using the embedded
// self-signed test certificate. They only build meaningfully when the
// msquic backend is compiled in (-Dtransport=msquic|both); on a
// grpc-only build the whole suite degrades to a single "backend not
// linked" assertion.
//
// Increment 2 covers the unary path. Increments 3+ extend this file with
// bidi, deadline, mTLS, metric-sink, and pool cases.

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <string_view>

#include "yuzu/transport/transport.hpp"

#ifdef YUZU_TRANSPORT_HAVE_MSQUIC
#include "test_certs.hpp"
#endif

using namespace yuzu::transport;

namespace {

// Minimal SerializableMessage carrying an opaque byte string — the same
// shape as test_transport_smoke.cpp's StringMessage, duplicated here so
// this suite stays free of the gRPC-specific includes in that file.
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

} // namespace

#ifdef YUZU_TRANSPORT_HAVE_MSQUIC

TEST_CASE("msquic unary round-trip with registered handler", "[transport][msquic][round-trip]") {
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    // Server handler: echoes the request bytes back, prefixed with "ack:".
    auto handler = [](const CallContext&, const SerializableMessage& req,
                      SerializableMessage& resp) -> Status {
        const auto& sreq = static_cast<const StringMessage&>(req);
        auto& sresp = static_cast<StringMessage&>(resp);
        sresp.set_data("ack:" + sreq.data());
        return Status{StatusCode::Ok, ""};
    };
    auto factory = []() -> std::unique_ptr<SerializableMessage> {
        return std::make_unique<StringMessage>();
    };
    listener->register_unary("yuzu.test.v1.Echo/Echo", factory, factory, handler);

    // Increment-2 scope: server-auth-only TLS with the embedded
    // self-signed cert; the client does not verify the peer.
    Credentials creds{};
    creds.server_cert_pem = test::kTestServerCertPem;
    creds.server_key_pem = test::kTestServerKeyPem;
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;

    Endpoint bind{"127.0.0.1", 0}; // ephemeral port
    auto start_r = listener->start(bind, creds);
    REQUIRE(start_r.has_value());
    REQUIRE(listener->is_serving());
    Endpoint bound = listener->bound_endpoint();
    REQUIRE(bound.port != 0);

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    StringMessage req("hello"), resp;
    CallContext ctx;
    auto r = ch->unary("yuzu.test.v1.Echo/Echo", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Ok);
    REQUIRE(resp.data() == "ack:hello");

    ch->close();
    listener->shutdown();
    REQUIRE_FALSE(listener->is_serving());
}

TEST_CASE("msquic unary returns Unimplemented for an unknown method",
          "[transport][msquic][round-trip]") {
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    // A handler is registered, but the client calls a different method.
    auto handler = [](const CallContext&, const SerializableMessage&,
                      SerializableMessage&) -> Status {
        return Status{StatusCode::Ok, ""};
    };
    auto factory = []() -> std::unique_ptr<SerializableMessage> {
        return std::make_unique<StringMessage>();
    };
    listener->register_unary("yuzu.test.v1.Echo/Echo", factory, factory, handler);

    Credentials creds{};
    creds.server_cert_pem = test::kTestServerCertPem;
    creds.server_key_pem = test::kTestServerKeyPem;
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;

    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();
    REQUIRE(bound.port != 0);

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    StringMessage req("hello"), resp;
    CallContext ctx;
    // The failure-path wire contract: a single TrailingStatus frame, no
    // response frame.
    auto r = ch->unary("yuzu.test.v1.Echo/DoesNotExist", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Unimplemented);

    ch->close();
    listener->shutdown();
}

#else // !YUZU_TRANSPORT_HAVE_MSQUIC

TEST_CASE("msquic backend not linked into this build", "[transport][msquic][round-trip]") {
    // -Dtransport=grpc: the msquic factory returns nullptr. The framing
    // codec suite still runs (it has no msquic dependency).
    auto ch = make_channel(Backend::Msquic, Endpoint{"127.0.0.1", 0}, Credentials{});
    REQUIRE(ch == nullptr);
}

#endif // YUZU_TRANSPORT_HAVE_MSQUIC
