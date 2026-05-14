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
// Increment 2 covers the unary path (happy path, unknown method,
// handler-returned error, request parse failure, handler-thrown
// exception). Increments 3+ extend this file with bidi, deadline, mTLS,
// metric-sink, and pool cases.

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

#include "test_transport_helpers.hpp" // yuzu::transport::test::StringMessage
#include "yuzu/transport/transport.hpp"

#ifdef YUZU_TRANSPORT_HAVE_MSQUIC
#include "test_certs.hpp"
#endif

using namespace yuzu::transport;
using yuzu::transport::test::StringMessage;

#ifdef YUZU_TRANSPORT_HAVE_MSQUIC

namespace {

// Increment-2 scope: server-auth-only TLS with the embedded self-signed
// cert; the client does not verify the peer. Shared by every case here.
Credentials make_test_creds() {
    Credentials creds{};
    creds.server_cert_pem = test::kTestServerCertPem;
    creds.server_key_pem = test::kTestServerKeyPem;
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    return creds;
}

std::unique_ptr<SerializableMessage> string_factory() {
    return std::make_unique<StringMessage>();
}

} // namespace

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
    listener->register_unary("yuzu.test.v1.Echo/Echo", string_factory, string_factory, handler);

    Credentials creds = make_test_creds();
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

    auto handler = [](const CallContext&, const SerializableMessage&,
                      SerializableMessage&) -> Status {
        return Status{StatusCode::Ok, ""};
    };
    listener->register_unary("yuzu.test.v1.Echo/Echo", string_factory, string_factory, handler);

    Credentials creds = make_test_creds();
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();
    REQUIRE(bound.port != 0);

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    StringMessage req("hello"), resp;
    CallContext ctx;
    // Failure-path wire contract: a single TrailingStatus frame, no
    // response frame. The detail string is asserted so it stays in lock-
    // step with the gRPC backend's verbatim string (governance cons-N2).
    auto r = ch->unary("yuzu.test.v1.Echo/DoesNotExist", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Unimplemented);
    REQUIRE(r.status.detail == "transport: method not registered");

    ch->close();
    listener->shutdown();
}

TEST_CASE("msquic unary propagates a handler-returned error status",
          "[transport][msquic][round-trip]") {
    // governance qe-S2a: a non-Ok handler return must reach the client's
    // CallResult faithfully — code and detail — through send_trailing_status
    // -> parse_trailer, with no response frame on the wire.
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, const SerializableMessage&,
                      SerializableMessage&) -> Status {
        return Status{StatusCode::PermissionDenied, "operator denied"};
    };
    listener->register_unary("yuzu.test.v1.Echo/Denied", string_factory, string_factory, handler);

    Credentials creds = make_test_creds();
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();
    REQUIRE(bound.port != 0);

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    StringMessage req("x"), resp;
    CallContext ctx;
    auto r = ch->unary("yuzu.test.v1.Echo/Denied", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::PermissionDenied);
    REQUIRE(r.status.detail == "operator denied");

    ch->close();
    listener->shutdown();
}

TEST_CASE("msquic unary returns DataLoss when the request frame fails to parse",
          "[transport][msquic][round-trip]") {
    // governance qe-S2b: run_unary_handler maps a request->parse() failure
    // to DataLoss before the handler ever runs.
    struct ParseFailMessage final : SerializableMessage {
        bool serialize(std::string& out) const override {
            out.clear();
            return true;
        }
        bool parse(std::string_view) override { return false; }
    };

    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    bool handler_ran = false;
    auto handler = [&handler_ran](const CallContext&, const SerializableMessage&,
                                  SerializableMessage&) -> Status {
        handler_ran = true; // must NOT run — parse fails first
        return Status{StatusCode::Ok, ""};
    };
    auto fail_factory = []() -> std::unique_ptr<SerializableMessage> {
        return std::make_unique<ParseFailMessage>();
    };
    listener->register_unary("yuzu.test.v1.Echo/BadParse", fail_factory, string_factory, handler);

    Credentials creds = make_test_creds();
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();
    REQUIRE(bound.port != 0);

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    StringMessage req("anything"), resp;
    CallContext ctx;
    auto r = ch->unary("yuzu.test.v1.Echo/BadParse", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::DataLoss);
    REQUIRE_FALSE(handler_ran);

    ch->close();
    listener->shutdown();
}

TEST_CASE("msquic unary scrubs a handler-thrown exception off the wire",
          "[transport][msquic][round-trip]") {
    // governance qe-S2c: a handler that throws must surface to the client
    // as StatusCode::Internal with the static literal detail — the
    // exception's what() text must never cross the process boundary.
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, const SerializableMessage&,
                      SerializableMessage&) -> Status {
        throw std::runtime_error("SECRET_INTERNAL_DETAIL_/etc/shadow");
    };
    listener->register_unary("yuzu.test.v1.Echo/Throws", string_factory, string_factory, handler);

    Credentials creds = make_test_creds();
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();
    REQUIRE(bound.port != 0);

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    StringMessage req("x"), resp;
    CallContext ctx;
    auto r = ch->unary("yuzu.test.v1.Echo/Throws", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Internal);
    REQUIRE(r.status.detail == "transport: handler raised exception");
    REQUIRE(r.status.detail.find("SECRET_INTERNAL_DETAIL") == std::string::npos);

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
