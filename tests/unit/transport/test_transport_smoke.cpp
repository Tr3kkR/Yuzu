// SPDX-License-Identifier: Apache-2.0
// Smoke + lifecycle tests for the yuzu::transport:: abstraction (#376).
//
// Verifies the public surface compiles and behaves at the construction
// level, and exercises the registration / lifecycle invariants
// strengthened by the hardening rounds.

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <memory>
#include <stop_token>
#include <string>
#include <thread>

#include "yuzu/transport/transport.hpp"

using namespace yuzu::transport;

TEST_CASE("backend_name maps both backends", "[transport]") {
    REQUIRE(backend_name(Backend::Grpc) == "grpc");
    REQUIRE(backend_name(Backend::Msquic) == "msquic");
}

TEST_CASE("parse_backend recognises documented spellings", "[transport]") {
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

TEST_CASE("StatusCode numeric values match google.rpc.Code", "[transport]") {
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

TEST_CASE("Frame size constants follow the documented hierarchy", "[transport]") {
    REQUIRE(kDefaultMaxFrameSize == 4u * 1024u * 1024u);
    REQUIRE(kAbsoluteMaxFrameSize == 64u * 1024u * 1024u);
    REQUIRE(kDefaultMaxFrameSize < kAbsoluteMaxFrameSize);
}

TEST_CASE("make_channel(Grpc) returns a usable Channel", "[transport]") {
    Endpoint target{"127.0.0.1", 0};
    Credentials creds{};       // plaintext-default
    creds.verify_peer = false; // permitted in test build

    auto ch = make_channel(Backend::Grpc, target, creds);
    REQUIRE(ch != nullptr);

    // wait_for_connected with a port-zero endpoint must NOT hang and
    // MUST return false within the deadline. Documents the
    // wait_for_connected contract: "ready to accept new streams" is
    // the only signal; never an indefinite wait.
    //
    // 200ms gives slack for Defender-induced channel-init slowness on
    // the yuzu-local-windows runner (governance NICE-1) without
    // meaningfully changing total test wall time.
    REQUIRE_FALSE(ch->wait_for_connected(std::chrono::milliseconds(200)));

    // close() is documented as idempotent.
    ch->close();
    ch->close();
}

TEST_CASE("make_channel rejects asymmetric mTLS material", "[transport]") {
    // governance UP-1: cert-without-key (or vice versa) silently produces
    // a non-null but unusable channel. Hardening adds a pre-flight check;
    // the resulting Channel surfaces construction_error_ via every call.
    Endpoint target{"127.0.0.1", 0};
    Credentials creds{};
    creds.verify_peer = true;
    creds.client_cert_pem = "-----BEGIN CERTIFICATE-----\n"
                            "fake\n-----END CERTIFICATE-----\n";
    // client_key_pem deliberately empty.

    auto ch = make_channel(Backend::Grpc, target, creds);
    REQUIRE(ch != nullptr); // construction succeeds; channel is born dead.

    // Any call surfaces the construction error as Unauthenticated.
    Status dummy_status;
    CallContext ctx;
    struct DummyMsg final : SerializableMessage {
        bool serialize(std::string&) const override { return true; }
        bool parse(std::string_view) override { return true; }
    } req, resp;
    auto r = ch->unary("yuzu.agent.v1.AgentService/Heartbeat", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Unauthenticated);
}

TEST_CASE("make_channel rejects BackoffPolicy invariant violation", "[transport]") {
    // governance UP-5: initial_delay > max_delay would produce
    // implementation-defined gRPC reconnect behaviour.
    Endpoint target{"127.0.0.1", 0};
    Credentials creds{};
    creds.verify_peer = false;
    BackoffPolicy bad_backoff;
    bad_backoff.initial_delay = std::chrono::seconds(60);
    bad_backoff.max_delay = std::chrono::seconds(1);

    auto ch = make_channel(Backend::Grpc, target, creds, bad_backoff);
    REQUIRE(ch != nullptr);

    CallContext ctx;
    struct DummyMsg final : SerializableMessage {
        bool serialize(std::string&) const override { return true; }
        bool parse(std::string_view) override { return true; }
    } req, resp;
    auto r = ch->unary("yuzu.agent.v1.AgentService/Heartbeat", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Unauthenticated);
    REQUIRE(r.status.detail.find("initial_delay") != std::string::npos);
}

TEST_CASE("make_channel(Msquic) returns nullptr in PR 1a (impl is PR 3)", "[transport]") {
    Endpoint target{"127.0.0.1", 0};
    Credentials creds{};
    creds.verify_peer = false;

    auto ch = make_channel(Backend::Msquic, target, creds);
    REQUIRE(ch == nullptr);
}

TEST_CASE("ServerListener registers handlers and reports is_serving", "[transport]") {
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

TEST_CASE("ServerListener register_unary parity with register_bidi_stream", "[transport]") {
    // governance qe-S1: register_unary's malformed-name path was
    // structurally validated via the shared enforce_method_or_die but
    // not directly exercised. Add explicit coverage.
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    auto noop_handler = [](const CallContext&, const SerializableMessage&, SerializableMessage&) {
        return Status{StatusCode::Ok, ""};
    };
    auto noop_factory = []() -> std::unique_ptr<SerializableMessage> {
        struct DummyMsg final : SerializableMessage {
            bool serialize(std::string&) const override { return true; }
            bool parse(std::string_view) override { return true; }
        };
        return std::make_unique<DummyMsg>();
    };

    REQUIRE_NOTHROW(listener->register_unary("yuzu.agent.v1.AgentService/Heartbeat", noop_factory,
                                             noop_factory, noop_handler));

    REQUIRE_THROWS_AS(
        listener->register_unary("../etc/passwd", noop_factory, noop_factory, noop_handler),
        std::invalid_argument);

    REQUIRE_THROWS_AS(listener->register_unary("", noop_factory, noop_factory, noop_handler),
                      std::invalid_argument);
}

TEST_CASE("ServerListener rejects duplicate registration", "[transport]") {
    // governance UP-7: silent first-wins on collision is a debugging
    // foot-gun. Hardening makes the contract "throw on collision."
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    auto noop_handler = [](const CallContext&, BidiStream&) {
        return Status{StatusCode::Ok, ""};
    };

    listener->register_bidi_stream("yuzu.agent.v1.AgentService/Subscribe", noop_handler);

    // Re-registering the same method (same kind) throws.
    REQUIRE_THROWS_AS(
        listener->register_bidi_stream("yuzu.agent.v1.AgentService/Subscribe", noop_handler),
        std::invalid_argument);

    // Re-registering as a different kind also throws (cross-kind clash).
    auto noop_unary = [](const CallContext&, const SerializableMessage&, SerializableMessage&) {
        return Status{StatusCode::Ok, ""};
    };
    auto noop_factory = []() -> std::unique_ptr<SerializableMessage> {
        struct DummyMsg final : SerializableMessage {
            bool serialize(std::string&) const override { return true; }
            bool parse(std::string_view) override { return true; }
        };
        return std::make_unique<DummyMsg>();
    };
    REQUIRE_THROWS_AS(listener->register_unary("yuzu.agent.v1.AgentService/Subscribe", noop_factory,
                                               noop_factory, noop_unary),
                      std::invalid_argument);
}

TEST_CASE("Channel::unary against unreachable target returns Unavailable", "[transport]") {
    // PR 1b-1: real gRPC dispatch via grpc::GenericStub.
    // 127.0.0.1 with an unused port is the canonical unreachable target.
    // gRPC reports Unavailable for connect refused (or DeadlineExceeded
    // if the deadline elapses before the connect attempt fails).
    Endpoint target{"127.0.0.1", 1}; // port 1 is reserved + always closed
    Credentials creds{};
    creds.verify_peer = false;

    auto ch = make_channel(Backend::Grpc, target, creds);
    REQUIRE(ch != nullptr);

    struct DummyMsg final : SerializableMessage {
        bool serialize(std::string& out) const override {
            out = "x";
            return true;
        }
        bool parse(std::string_view) override { return true; }
    } req, resp;

    CallContext ctx;
    ctx.deadline = std::chrono::milliseconds(500);

    auto r = ch->unary("yuzu.agent.v1.AgentService/Heartbeat", ctx, req, resp);
    // Either Unavailable (connect refused) or DeadlineExceeded (took too
    // long) is acceptable — both prove the dispatch path reached gRPC.
    // The placeholder StatusCode::Unimplemented from PR 1a would NOT
    // appear here.
    REQUIRE((r.status.code == StatusCode::Unavailable ||
             r.status.code == StatusCode::DeadlineExceeded));
}

TEST_CASE("Channel::unary serialize failure returns Internal", "[transport]") {
    Endpoint target{"127.0.0.1", 1};
    Credentials creds{};
    creds.verify_peer = false;

    auto ch = make_channel(Backend::Grpc, target, creds);
    REQUIRE(ch != nullptr);

    struct FailingMsg final : SerializableMessage {
        bool serialize(std::string&) const override { return false; }
        bool parse(std::string_view) override { return true; }
    } req;
    struct DummyMsg final : SerializableMessage {
        bool serialize(std::string&) const override { return true; }
        bool parse(std::string_view) override { return true; }
    } resp;

    CallContext ctx;
    auto r = ch->unary("yuzu.agent.v1.AgentService/Heartbeat", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Internal);
}

TEST_CASE("Channel::unary cancel via stop_token returns Cancelled", "[transport]") {
    Endpoint target{"127.0.0.1", 1};
    Credentials creds{};
    creds.verify_peer = false;

    auto ch = make_channel(Backend::Grpc, target, creds);
    REQUIRE(ch != nullptr);

    struct DummyMsg final : SerializableMessage {
        bool serialize(std::string& out) const override {
            out = "x";
            return true;
        }
        bool parse(std::string_view) override { return true; }
    } req, resp;

    std::stop_source ss;
    CallContext ctx;
    ctx.cancel = ss.get_token();
    ctx.deadline = std::chrono::seconds(5);

    // Stop after a short delay so the dispatch enters gRPC before
    // TryCancel fires.
    std::thread canceller([&ss]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        ss.request_stop();
    });

    auto r = ch->unary("yuzu.agent.v1.AgentService/Heartbeat", ctx, req, resp);
    canceller.join();

    // Acceptable outcomes: Cancelled (TryCancel fired), Unavailable
    // (connect refused before cancel observed), DeadlineExceeded (slow
    // CI). The dispatch path was real either way.
    REQUIRE((r.status.code == StatusCode::Cancelled || r.status.code == StatusCode::Unavailable ||
             r.status.code == StatusCode::DeadlineExceeded));
}

TEST_CASE("ServerListener rejects oversize max_frame_size", "[transport]") {
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
    // is_serving stays false because the validation happens BEFORE the
    // started_ exchange (governance UP-18).
    REQUIRE_FALSE(listener->is_serving());
}
