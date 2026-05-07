// SPDX-License-Identifier: Apache-2.0
// Smoke tests for the yuzu::transport:: abstraction (#376 PR 1a).
//
// Verifies that the abstraction's public surface compiles and behaves
// at the construction level. RPC dispatch tests (unary, bidi) are
// added in PR 1b once grpc::GenericStub wiring lands.

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <memory>

#include "yuzu/transport/transport.hpp"

using namespace yuzu::transport;

TEST_CASE("backend_name maps both backends", "[transport][smoke]") {
    REQUIRE(backend_name(Backend::Grpc) == "grpc");
    REQUIRE(backend_name(Backend::Msquic) == "msquic");
}

TEST_CASE("parse_backend recognises documented spellings", "[transport][smoke]") {
    auto g = parse_backend("grpc");
    REQUIRE(g.has_value());
    REQUIRE(g.value() == Backend::Grpc);

    auto m = parse_backend("msquic");
    REQUIRE(m.has_value());
    REQUIRE(m.value() == Backend::Msquic);

    // PR 5 alias — operator-facing --transport=quic resolves to msquic.
    auto q = parse_backend("quic");
    REQUIRE(q.has_value());
    REQUIRE(q.value() == Backend::Msquic);

    auto bad = parse_backend("ftp");
    REQUIRE_FALSE(bad.has_value());
    REQUIRE(bad.error().code == StatusCode::InvalidArgument);
}

TEST_CASE("StatusCode numeric values match google.rpc.Code", "[transport][smoke]") {
    // Wire-stability commitment: the integer values are FROZEN to match
    // google.rpc.Code / grpc::StatusCode. PR 1b will harden this with
    // a static_assert against the generated proto enum; the smoke
    // assertions below catch the obvious drift cases.
    REQUIRE(static_cast<int>(StatusCode::Ok) == 0);
    REQUIRE(static_cast<int>(StatusCode::Cancelled) == 1);
    REQUIRE(static_cast<int>(StatusCode::InvalidArgument) == 3);
    REQUIRE(static_cast<int>(StatusCode::DeadlineExceeded) == 4);
    REQUIRE(static_cast<int>(StatusCode::Unimplemented) == 12);
    REQUIRE(static_cast<int>(StatusCode::Unavailable) == 14);
    REQUIRE(static_cast<int>(StatusCode::Unauthenticated) == 16);
}

TEST_CASE("Frame size constants follow the documented hierarchy", "[transport][smoke]") {
    REQUIRE(kDefaultMaxFrameSize == 4u * 1024u * 1024u);
    REQUIRE(kAbsoluteMaxFrameSize == 64u * 1024u * 1024u);
    REQUIRE(kDefaultMaxFrameSize < kAbsoluteMaxFrameSize);
}

TEST_CASE("make_channel(Grpc) returns a usable Channel", "[transport][smoke]") {
    Endpoint target{"127.0.0.1", 0};
    Credentials creds{};       // plaintext-default
    creds.verify_peer = false; // permitted in test build

    auto ch = make_channel(Backend::Grpc, target, creds);
    REQUIRE(ch != nullptr);

    // wait_for_connected with a port-zero endpoint must NOT hang and
    // MUST return false within the deadline. Documents the
    // wait_for_connected contract: "ready to accept new streams" is
    // the only signal; never an indefinite wait.
    REQUIRE_FALSE(ch->wait_for_connected(std::chrono::milliseconds(50)));

    // close() is documented as idempotent.
    ch->close();
    ch->close();
}

TEST_CASE("make_channel(Msquic) returns nullptr in PR 1a (impl is PR 3)", "[transport][smoke]") {
    Endpoint target{"127.0.0.1", 0};
    Credentials creds{};
    creds.verify_peer = false;

    auto ch = make_channel(Backend::Msquic, target, creds);
    REQUIRE(ch == nullptr);
}

TEST_CASE("ServerListener registers handlers and reports is_serving", "[transport][smoke]") {
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);
    REQUIRE_FALSE(listener->is_serving());

    // Registration with a well-formed method name succeeds.
    listener->register_bidi_stream("yuzu.agent.v1.AgentService/Subscribe",
                                   [](const CallContext&, BidiStream&) {
                                       return Status{StatusCode::Ok, ""};
                                   });

    // Malformed method name throws (per the regex contract).
    REQUIRE_THROWS_AS(listener->register_bidi_stream("../etc/passwd",
                                                     [](const CallContext&, BidiStream&) {
                                                         return Status{StatusCode::Ok, ""};
                                                     }),
                      std::invalid_argument);

    // Empty method name throws.
    REQUIRE_THROWS_AS(listener->register_bidi_stream("",
                                                     [](const CallContext&, BidiStream&) {
                                                         return Status{StatusCode::Ok, ""};
                                                     }),
                      std::invalid_argument);

    // Idempotent shutdown of a never-started listener.
    listener->shutdown();
    listener->shutdown();
    REQUIRE_FALSE(listener->is_serving());
}

TEST_CASE("ServerListener rejects oversize max_frame_size", "[transport][smoke]") {
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};

    ListenerOptions opts;
    opts.max_frame_size = kAbsoluteMaxFrameSize + 1;

    auto r = listener->start(bind, creds, opts);
    REQUIRE_FALSE(r.has_value());
    REQUIRE(r.error().code == StatusCode::InvalidArgument);
}
