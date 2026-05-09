// SPDX-License-Identifier: Apache-2.0
// Smoke + lifecycle tests for the yuzu::transport:: abstraction (#376).
//
// Verifies the public surface compiles and behaves at the construction
// level, and exercises the registration / lifecycle invariants
// strengthened by the hardening rounds.

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <future>
#include <memory>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "transport.pb.h" // generated from proto/yuzu/transport/framing/v1/transport.proto
#include "yuzu/transport/proto_adapter.hpp"
#include "yuzu/transport/transport.hpp"

using namespace yuzu::transport;

TEST_CASE("backend_name maps both backends", "[transport][factory]") {
    REQUIRE(backend_name(Backend::Grpc) == "grpc");
    REQUIRE(backend_name(Backend::Msquic) == "msquic");
}

TEST_CASE("parse_backend recognises documented spellings", "[transport][factory]") {
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

TEST_CASE("StatusCode numeric values match google.rpc.Code", "[transport][factory]") {
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

TEST_CASE("Frame size constants follow the documented hierarchy", "[transport][factory]") {
    REQUIRE(kDefaultMaxFrameSize == 4u * 1024u * 1024u);
    REQUIRE(kAbsoluteMaxFrameSize == 64u * 1024u * 1024u);
    REQUIRE(kDefaultMaxFrameSize < kAbsoluteMaxFrameSize);
}

TEST_CASE("make_channel(Grpc) returns a usable Channel", "[transport][factory]") {
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

TEST_CASE("make_channel rejects asymmetric mTLS material", "[transport][dispatch]") {
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

TEST_CASE("make_channel rejects BackoffPolicy invariant violation", "[transport][dispatch]") {
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

TEST_CASE("make_channel(Msquic) returns nullptr in PR 1a (impl is PR 3)", "[transport][factory]") {
    Endpoint target{"127.0.0.1", 0};
    Credentials creds{};
    creds.verify_peer = false;

    auto ch = make_channel(Backend::Msquic, target, creds);
    REQUIRE(ch == nullptr);
}

TEST_CASE("ServerListener registers handlers and reports is_serving", "[transport][lifecycle]") {
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

TEST_CASE("ServerListener register_unary parity with register_bidi_stream",
          "[transport][lifecycle]") {
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

TEST_CASE("ServerListener rejects duplicate registration", "[transport][lifecycle]") {
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

TEST_CASE("Channel::unary against unreachable target returns Unavailable",
          "[transport][dispatch]") {
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

TEST_CASE("Channel::unary serialize failure returns Internal", "[transport][dispatch]") {
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

TEST_CASE("Channel::unary cancel via stop_token returns Cancelled", "[transport][dispatch]") {
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

// =====================================================================
// Round-trip tests (PR 1b-2): client unary dispatch ↔ server
// AsyncGenericService dispatcher
// =====================================================================
//
// These tests start a real listener on 127.0.0.1 with an ephemeral port,
// register a unary handler, connect a Channel via make_channel, and
// invoke unary() — exercising the full async state machine end to end.

namespace {

// Adapter: SerializableMessage that owns a std::string payload.
// Used by both client (request/response) and server (handler) sides.
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

// Round-trip tests bind 127.0.0.1 with port 0 (ephemeral). After a
// successful start(), listener->bound_endpoint() returns the
// OS-assigned port; tests then connect a Channel against that port.
// This eliminates the TIME_WAIT / CI-rerun flakiness of fixed ports
// (governance qe-F1).

} // namespace

TEST_CASE("Client/server unary round-trip with registered handler", "[transport][round-trip]") {
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    // Server-side handler: echoes request bytes back, prefixed with "ack:".
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

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0}; // ephemeral port — avoids TIME_WAIT flake
    auto start_r = listener->start(bind, creds);
    REQUIRE(start_r.has_value());
    REQUIRE(listener->is_serving());
    Endpoint bound = listener->bound_endpoint();
    REQUIRE(bound.port != 0);

    // Client side
    auto ch = make_channel(Backend::Grpc, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    StringMessage req("hello"), resp;
    CallContext ctx;
    ctx.deadline = std::chrono::seconds(2);
    auto r = ch->unary("yuzu.test.v1.Echo/Echo", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Ok);
    REQUIRE(resp.data() == "ack:hello");

    ch->close();
    listener->shutdown();
    REQUIRE_FALSE(listener->is_serving());
}

TEST_CASE("Client/server unary returns Unimplemented for unknown method",
          "[transport][round-trip]") {
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    auto start_r = listener->start(bind, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Grpc, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    StringMessage req("hello"), resp;
    CallContext ctx;
    ctx.deadline = std::chrono::seconds(2);
    auto r = ch->unary("yuzu.test.v1.Echo/NotRegistered", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Unimplemented);

    ch->close();
    listener->shutdown();
}

TEST_CASE("Client/server unary propagates handler-returned error status",
          "[transport][round-trip]") {
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, const SerializableMessage&,
                      SerializableMessage&) -> Status {
        return Status{StatusCode::PermissionDenied, "no soup for you"};
    };
    auto factory = []() -> std::unique_ptr<SerializableMessage> {
        return std::make_unique<StringMessage>();
    };
    listener->register_unary("yuzu.test.v1.Echo/Forbidden", factory, factory, handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    auto start_r = listener->start(bind, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Grpc, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    StringMessage req, resp;
    CallContext ctx;
    ctx.deadline = std::chrono::seconds(2);
    auto r = ch->unary("yuzu.test.v1.Echo/Forbidden", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::PermissionDenied);
    REQUIRE(r.status.detail == "no soup for you");

    ch->close();
    listener->shutdown();
}

TEST_CASE("Client/server unary scrubs handler-thrown what() before wire",
          "[transport][round-trip]") {
    // governance sec-F1: handler exception what() must NOT cross the wire.
    // The dispatcher returns Internal with a static "handler raised exception"
    // string; the original what() is logged server-side, never sent.
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, const SerializableMessage&,
                      SerializableMessage&) -> Status {
        throw std::runtime_error("INTERNAL_DEPLOYMENT_PATH=/etc/secret");
    };
    auto factory = []() -> std::unique_ptr<SerializableMessage> {
        return std::make_unique<StringMessage>();
    };
    listener->register_unary("yuzu.test.v1.Echo/Throws", factory, factory, handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    auto start_r = listener->start(bind, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Grpc, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    StringMessage req, resp;
    CallContext ctx;
    ctx.deadline = std::chrono::seconds(2);
    auto r = ch->unary("yuzu.test.v1.Echo/Throws", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Internal);
    // Static summary, NOT the what() text that contained INTERNAL_DEPLOYMENT_PATH.
    REQUIRE(r.status.detail.find("INTERNAL_DEPLOYMENT_PATH") == std::string::npos);
    REQUIRE(r.status.detail.find("/etc/secret") == std::string::npos);
    REQUIRE(r.status.detail.find("handler raised") != std::string::npos);

    ch->close();
    listener->shutdown();
}

TEST_CASE("Client/server unary serialises N concurrent calls cleanly", "[transport][round-trip]") {
    // governance qe-F5: dispatcher thread-safety under concurrent load.
    // The cq_worker is single-threaded so handlers serialise; this test
    // proves no race in the state machine and no leak across N completions.
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, const SerializableMessage& req,
                      SerializableMessage& resp) -> Status {
        const auto& sreq = static_cast<const StringMessage&>(req);
        auto& sresp = static_cast<StringMessage&>(resp);
        sresp.set_data("ok:" + sreq.data());
        return Status{StatusCode::Ok, ""};
    };
    auto factory = []() -> std::unique_ptr<SerializableMessage> {
        return std::make_unique<StringMessage>();
    };
    listener->register_unary("yuzu.test.v1.Echo/Concurrent", factory, factory, handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    auto start_r = listener->start(bind, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    constexpr int N = 8;
    std::vector<std::future<Status>> futures;
    for (int i = 0; i < N; ++i) {
        futures.push_back(std::async(std::launch::async, [bound, &creds, i] {
            auto ch = make_channel(Backend::Grpc, bound, creds);
            ch->wait_for_connected(std::chrono::seconds(2));
            StringMessage req(std::to_string(i)), resp;
            CallContext ctx;
            ctx.deadline = std::chrono::seconds(5);
            auto r = ch->unary("yuzu.test.v1.Echo/Concurrent", ctx, req, resp);
            return r.status;
        }));
    }
    for (auto& f : futures) {
        REQUIRE(f.get().code == StatusCode::Ok);
    }

    listener->shutdown();
}

TEST_CASE("Client receives sanitised Status::detail on attacker-controlled bytes",
          "[transport][round-trip]") {
    // governance round 5 sec-1 / UP-41 / arch-1 / cons-G4-2: Status::detail
    // is wire data and must be scrubbed BOTH outbound (already covered by
    // the handler-throws test above) AND inbound. A malicious or buggy
    // peer can otherwise feed control bytes / non-ASCII into Prometheus
    // label cardinality, audit-log rows, and dashboard SSE renders.
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    // Handler returns a Status whose detail contains CR, LF, NUL, a high
    // byte, and a header-injection payload. The dispatcher's `to_grpc_status`
    // helper scrubs on outbound; this test additionally proves that even
    // if an outbound scrub regresses, the CLIENT's inbound scrub catches
    // the same bytes — symmetric defence.
    auto handler = [](const CallContext&, const SerializableMessage&,
                      SerializableMessage&) -> Status {
        return Status{StatusCode::Internal, std::string("\r\nX-Injected: yes\x00\x01\x80malicious",
                                                        /*size=*/29)};
    };
    auto factory = []() -> std::unique_ptr<SerializableMessage> {
        return std::make_unique<StringMessage>();
    };
    listener->register_unary("yuzu.test.v1.Echo/InjectDetail", factory, factory, handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    auto start_r = listener->start(bind, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Grpc, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    StringMessage req, resp;
    CallContext ctx;
    ctx.deadline = std::chrono::seconds(2);
    auto r = ch->unary("yuzu.test.v1.Echo/InjectDetail", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Internal);

    // No control bytes survive in the client-observed detail.
    for (const char c : r.status.detail) {
        const auto u = static_cast<unsigned char>(c);
        REQUIRE((u >= 0x20 && u < 0x7F));
    }
    // Header-injection payload's printable ASCII would survive (the scrub
    // only replaces non-printable bytes), but the CRLF that would
    // separate it from a fake header is gone.
    REQUIRE(r.status.detail.find('\r') == std::string::npos);
    REQUIRE(r.status.detail.find('\n') == std::string::npos);
    REQUIRE(r.status.detail.find('\0') == std::string::npos);

    ch->close();
    listener->shutdown();
}

// =====================================================================
// PR 1b-3 — bidi round-trip
// =====================================================================

TEST_CASE("Client/server bidi round-trip echoes N frames", "[transport][round-trip][bidi]") {
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, BidiStream& stream) -> Status {
        StringMessage msg;
        while (stream.read(msg)) {
            StringMessage out("echo:" + msg.data());
            if (!stream.write(out)) {
                return Status{StatusCode::Internal, "write failed"};
            }
        }
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/BidiEcho", handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    auto start_r = listener->start(bind, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Grpc, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    CallContext ctx;
    ctx.deadline = std::chrono::seconds(5);
    auto stream = ch->bidi_stream("yuzu.test.v1.Echo/BidiEcho", ctx);
    REQUIRE(stream != nullptr);

    constexpr int N = 5;
    for (int i = 0; i < N; ++i) {
        StringMessage out(std::to_string(i));
        REQUIRE(stream->write(out));
        StringMessage in;
        REQUIRE(stream->read(in));
        REQUIRE(in.data() == "echo:" + std::to_string(i));
    }
    stream->writes_done();

    StringMessage drain;
    REQUIRE_FALSE(stream->read(drain)); // peer half-close after handler returns

    Status final = stream->final_status();
    REQUIRE(final.code == StatusCode::Ok);

    listener->shutdown();
}

TEST_CASE("Client/server bidi propagates handler error status", "[transport][round-trip][bidi]") {
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, BidiStream& stream) -> Status {
        StringMessage msg;
        (void)stream.read(msg);
        return Status{StatusCode::PermissionDenied, "no soup for you"};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/BidiForbidden", handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    REQUIRE(listener->start(bind, creds).has_value());
    auto ch = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    CallContext ctx;
    ctx.deadline = std::chrono::seconds(2);
    auto stream = ch->bidi_stream("yuzu.test.v1.Echo/BidiForbidden", ctx);
    REQUIRE(stream != nullptr);

    StringMessage out("hi");
    stream->write(out);
    stream->writes_done();
    StringMessage in;
    REQUIRE_FALSE(stream->read(in));
    Status final = stream->final_status();
    REQUIRE(final.code == StatusCode::PermissionDenied);
    REQUIRE(final.detail == "no soup for you");

    listener->shutdown();
}

TEST_CASE("Bidi stream cancel via stop_token aborts in-flight read",
          "[transport][round-trip][bidi]") {
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, BidiStream& stream) -> Status {
        // Block on read until peer cancels.
        StringMessage msg;
        while (stream.read(msg)) {
            // echo if any frames arrive
            StringMessage out("ack");
            stream.write(out);
        }
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/BidiBlock", handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    REQUIRE(listener->start(bind, creds).has_value());
    auto ch = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    std::stop_source ss;
    CallContext ctx;
    ctx.cancel = ss.get_token();
    ctx.deadline = std::chrono::seconds(5);
    auto stream = ch->bidi_stream("yuzu.test.v1.Echo/BidiBlock", ctx);
    REQUIRE(stream != nullptr);

    std::thread canceller([&ss]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        ss.request_stop();
    });

    StringMessage in;
    // Read should observe the cancel and return false.
    REQUIRE_FALSE(stream->read(in));
    canceller.join();

    Status final = stream->final_status();
    // Cancelled is the expected mapping; a fast Unavailable is also
    // acceptable if gRPC saw the connection drop first.
    REQUIRE((final.code == StatusCode::Cancelled || final.code == StatusCode::Unavailable));

    listener->shutdown();
}

TEST_CASE("Bidi unknown method returns Unimplemented", "[transport][round-trip][bidi]") {
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    REQUIRE(listener->start(bind, creds).has_value());
    auto ch = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    CallContext ctx;
    ctx.deadline = std::chrono::seconds(2);
    auto stream = ch->bidi_stream("yuzu.test.v1.Echo/BidiNotRegistered", ctx);
    REQUIRE(stream != nullptr);
    stream->writes_done();
    StringMessage in;
    REQUIRE_FALSE(stream->read(in));
    Status final = stream->final_status();
    REQUIRE(final.code == StatusCode::Unimplemented);

    listener->shutdown();
}

TEST_CASE("Bidi handler-thrown what() is scrubbed before wire", "[transport][round-trip][bidi]") {
    // Symmetric with the unary sec-F1 test — handler's std::exception
    // text must NEVER reach the wire.
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, BidiStream& stream) -> Status {
        StringMessage msg;
        (void)stream.read(msg);
        throw std::runtime_error("INTERNAL_DEPLOYMENT_PATH=/etc/secret");
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/BidiThrows", handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    REQUIRE(listener->start(bind, creds).has_value());
    auto ch = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    CallContext ctx;
    ctx.deadline = std::chrono::seconds(2);
    auto stream = ch->bidi_stream("yuzu.test.v1.Echo/BidiThrows", ctx);
    REQUIRE(stream != nullptr);
    StringMessage out("ping");
    stream->write(out);
    stream->writes_done();
    StringMessage in;
    REQUIRE_FALSE(stream->read(in));
    Status final = stream->final_status();
    REQUIRE(final.code == StatusCode::Internal);
    REQUIRE(final.detail.find("INTERNAL_DEPLOYMENT_PATH") == std::string::npos);
    REQUIRE(final.detail.find("/etc/secret") == std::string::npos);
    REQUIRE(final.detail.find("handler raised") != std::string::npos);

    listener->shutdown();
}

TEST_CASE("Bidi concurrent reader thread + writer thread coexist",
          "[transport][round-trip][bidi]") {
    // governance qe-SHOULD: the threading contract in transport.hpp
    // permits a single-reader thread to run concurrent with a
    // single-writer thread. Earlier bidi tests drove both halves from
    // one caller thread; this test pins the dual-thread shape so a
    // future deadlock between read+write cv waits would surface here.
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    constexpr int N = 16;
    auto handler = [](const CallContext&, BidiStream& stream) -> Status {
        StringMessage msg;
        while (stream.read(msg)) {
            StringMessage out("ack:" + msg.data());
            if (!stream.write(out))
                return Status{StatusCode::Internal, ""};
        }
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/BidiConc", handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    REQUIRE(listener->start(bind, creds).has_value());
    auto ch = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    CallContext ctx;
    ctx.deadline = std::chrono::seconds(10);
    auto stream = ch->bidi_stream("yuzu.test.v1.Echo/BidiConc", ctx);
    REQUIRE(stream != nullptr);

    std::vector<std::string> received;
    received.reserve(N);
    std::mutex received_mtx;

    auto reader = std::async(std::launch::async, [&] {
        for (int i = 0; i < N; ++i) {
            StringMessage in;
            if (!stream->read(in))
                break;
            std::lock_guard<std::mutex> lk(received_mtx);
            received.push_back(in.data());
        }
    });
    auto writer = std::async(std::launch::async, [&] {
        for (int i = 0; i < N; ++i) {
            StringMessage out("frame_" + std::to_string(i));
            if (!stream->write(out))
                break;
        }
        stream->writes_done();
    });
    writer.get();
    reader.get();
    REQUIRE(received.size() == static_cast<std::size_t>(N));
    for (int i = 0; i < N; ++i) {
        REQUIRE(received[i] == "ack:frame_" + std::to_string(i));
    }
    REQUIRE(stream->final_status().code == StatusCode::Ok);

    listener->shutdown();
}

TEST_CASE("Bidi server-stream pattern (client writes_done immediately, reads N)",
          "[transport][round-trip][bidi]") {
    // governance happy-path SHOULD #5: PR 1c-3 lifts ExecuteCommand /
    // SendCommand / WatchEvents / DownloadUpdate as server-stream RPCs
    // mapped onto BidiStream. The client immediately calls writes_done()
    // and reads frames. This test pins that shape today so PR 1c-3
    // lands on a verified abstraction surface.
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    constexpr int N = 5;
    auto handler = [](const CallContext&, BidiStream& stream) -> Status {
        // Server ignores the read half (peer half-closes immediately)
        // and emits N frames. Drain reads first to observe the
        // client's writes_done flushing.
        StringMessage drain;
        while (stream.read(drain)) {
            // server-streaming canonical: client should not write
            // anything; if it does, ignore.
        }
        for (int i = 0; i < N; ++i) {
            StringMessage out("server_frame_" + std::to_string(i));
            if (!stream.write(out))
                return Status{StatusCode::Internal, ""};
        }
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/ServerStream", handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    REQUIRE(listener->start(bind, creds).has_value());
    auto ch = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    CallContext ctx;
    ctx.deadline = std::chrono::seconds(5);
    auto stream = ch->bidi_stream("yuzu.test.v1.Echo/ServerStream", ctx);
    REQUIRE(stream != nullptr);

    // Server-stream shape: tell server we're done writing, then read.
    stream->writes_done();
    // writes_done() is documented as silently idempotent — calling
    // again should not throw or block.
    stream->writes_done();

    std::vector<std::string> received;
    StringMessage in;
    while (stream->read(in)) {
        received.push_back(in.data());
    }
    REQUIRE(received.size() == static_cast<std::size_t>(N));
    for (int i = 0; i < N; ++i) {
        REQUIRE(received[i] == "server_frame_" + std::to_string(i));
    }
    REQUIRE(stream->final_status().code == StatusCode::Ok);

    listener->shutdown();
}

TEST_CASE("Bidi stream destroyed without final_status terminates cleanly",
          "[transport][round-trip][bidi]") {
    // Lifetime invariant — dtor must cancel + drain the CQ even when
    // the caller forgets final_status().
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, BidiStream& stream) -> Status {
        StringMessage msg;
        while (stream.read(msg)) {}
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/BidiDrop", handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    REQUIRE(listener->start(bind, creds).has_value());
    auto ch = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    {
        CallContext ctx;
        ctx.deadline = std::chrono::seconds(2);
        auto stream = ch->bidi_stream("yuzu.test.v1.Echo/BidiDrop", ctx);
        REQUIRE(stream != nullptr);
        StringMessage out("x");
        stream->write(out);
        // No writes_done(); no final_status(). Dtor must clean up.
    }

    listener->shutdown();
}

// =====================================================================
// PR 1c-1 — typed-proto adapter helpers
// =====================================================================

TEST_CASE("register_unary_pb dispatches typed protos end to end", "[transport][adapter]") {
    namespace tpb = ::yuzu::transport::framing::v1;

    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    // Handler receives typed HandshakeHello, populates typed
    // TrailingStatus. No SerializableMessage downcasting at the call site.
    register_unary_pb<tpb::HandshakeHello, tpb::TrailingStatus>(
        *listener, "yuzu.test.v1.AdapterEcho/Echo",
        [](const CallContext&, const tpb::HandshakeHello& req,
           tpb::TrailingStatus& resp) -> Status {
            resp.set_code(tpb::STATUS_CODE_OK);
            resp.set_detail("hello:" + req.method());
            return Status{StatusCode::Ok, ""};
        });

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    REQUIRE(listener->start(bind, creds).has_value());

    auto ch = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    tpb::HandshakeHello req;
    req.set_method("yuzu.agent.v1.AgentService/Heartbeat");
    tpb::TrailingStatus resp;

    CallContext ctx;
    ctx.deadline = std::chrono::seconds(2);
    auto req_adapter = as_proto(req);
    auto resp_adapter = as_proto(resp);
    auto r = ch->unary("yuzu.test.v1.AdapterEcho/Echo", ctx, req_adapter, resp_adapter);
    REQUIRE(r.status.code == StatusCode::Ok);
    REQUIRE(resp.code() == tpb::STATUS_CODE_OK);
    REQUIRE(resp.detail() == "hello:yuzu.agent.v1.AgentService/Heartbeat");

    listener->shutdown();
}

TEST_CASE("read_pb / write_pb adapt bidi to typed protos", "[transport][adapter][bidi]") {
    namespace tpb = ::yuzu::transport::framing::v1;

    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    listener->register_bidi_stream("yuzu.test.v1.AdapterEcho/BidiEcho",
                                   [](const CallContext&, BidiStream& stream) -> Status {
                                       tpb::HandshakeHello in;
                                       while (read_pb(stream, in)) {
                                           tpb::TrailingStatus out;
                                           out.set_code(tpb::STATUS_CODE_OK);
                                           out.set_detail("ack:" + in.method());
                                           if (!write_pb(stream, out)) {
                                               return Status{StatusCode::Internal, "write failed"};
                                           }
                                       }
                                       return Status{StatusCode::Ok, ""};
                                   });

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    REQUIRE(listener->start(bind, creds).has_value());
    auto ch = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    CallContext ctx;
    ctx.deadline = std::chrono::seconds(5);
    auto stream = ch->bidi_stream("yuzu.test.v1.AdapterEcho/BidiEcho", ctx);
    REQUIRE(stream != nullptr);

    for (int i = 0; i < 3; ++i) {
        tpb::HandshakeHello out;
        out.set_method("frame_" + std::to_string(i));
        REQUIRE(write_pb(*stream, out));

        tpb::TrailingStatus in;
        REQUIRE(read_pb(*stream, in));
        REQUIRE(in.code() == tpb::STATUS_CODE_OK);
        REQUIRE(in.detail() == "ack:frame_" + std::to_string(i));
    }
    stream->writes_done();
    tpb::TrailingStatus drain;
    REQUIRE_FALSE(read_pb(*stream, drain));
    REQUIRE(stream->final_status().code == StatusCode::Ok);

    listener->shutdown();
}

TEST_CASE("OwnedProtoMessage parses + serialises round-trip", "[transport][adapter]") {
    namespace tpb = ::yuzu::transport::framing::v1;

    OwnedProtoMessage<tpb::HandshakeHello> owned;
    owned.value().set_method("yuzu.agent.v1.AgentService/Subscribe");

    std::string bytes;
    REQUIRE(owned.serialize(bytes));
    REQUIRE_FALSE(bytes.empty());

    OwnedProtoMessage<tpb::HandshakeHello> parsed;
    REQUIRE(parsed.parse(bytes));
    REQUIRE(parsed.value().method() == "yuzu.agent.v1.AgentService/Subscribe");

    // Wire-corrupt input fails parse() — caller must treat as DataLoss.
    OwnedProtoMessage<tpb::HandshakeHello> bad;
    // Garbage bytes: non-zero unknown wire type combinations.
    REQUIRE_FALSE(bad.parse(std::string_view("\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80", 10)));
}

TEST_CASE("Server CallContext exposes peer_uri + initial metadata to handler",
          "[transport][round-trip][callcontext]") {
    // PR 1c-2 prerequisite: lifted handlers in agent_service_impl.cpp need to
    // resolve their caller via CallContext alone — without grpc::ServerContext
    // the metadata lookup (kSessionMetadataKey) and peer-identity validation
    // (Subscribe peer-mismatch) cannot complete. Pin both fields so a future
    // backend swap (msquic, PR 3) does not silently drop them.
    namespace tpb = ::yuzu::transport::framing::v1;
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    std::string seen_peer_uri;
    std::string seen_session_md;
    register_unary_pb<tpb::HandshakeHello, tpb::TrailingStatus>(
        *listener, "yuzu.test.v1.CtxEcho/Echo",
        [&](const CallContext& ctx, const tpb::HandshakeHello&,
            tpb::TrailingStatus& resp) -> Status {
            seen_peer_uri = ctx.peer_uri;
            if (auto it = ctx.metadata.find("x-yuzu-session-id"); it != ctx.metadata.end()) {
                seen_session_md = it->second;
            }
            resp.set_code(tpb::STATUS_CODE_OK);
            return Status{StatusCode::Ok, ""};
        });

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    REQUIRE(listener->start(bind, creds).has_value());
    auto ch = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    tpb::HandshakeHello req;
    req.set_method("ignored");
    tpb::TrailingStatus resp;
    CallContext ctx;
    ctx.deadline = std::chrono::seconds(2);
    ctx.metadata["x-yuzu-session-id"] = "sess-abcd-1234";
    auto req_adapter = as_proto(req);
    auto resp_adapter = as_proto(resp);
    auto r = ch->unary("yuzu.test.v1.CtxEcho/Echo", ctx, req_adapter, resp_adapter);
    REQUIRE(r.status.code == StatusCode::Ok);
    REQUIRE_FALSE(seen_peer_uri.empty());
    // gRPC peer URIs are scheme-prefixed (ipv4:HOST:PORT, ipv6:..., unix:...)
    // — the legacy AgentServiceImpl::Register relies on that exact shape.
    REQUIRE((seen_peer_uri.starts_with("ipv4:") || seen_peer_uri.starts_with("ipv6:")));
    REQUIRE(seen_session_md == "sess-abcd-1234");

    listener->shutdown();
}

TEST_CASE("ServerListener rejects oversize max_frame_size", "[transport][lifecycle]") {
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

// =====================================================================
// #904 / UP-14 — bounded bidi dispatcher pool
// =====================================================================
//
// Pre-#904 the dispatcher spawned one std::thread per active bidi RPC
// (unbounded). The pool caps in-flight bidi handlers at
// ListenerOptions::bidi_dispatcher_pool_size, rejects overflow with
// StatusCode::ResourceExhausted, and reuses workers across calls so the
// total OS-thread budget is operator-controlled.

TEST_CASE("Bidi pool reuses workers across more sequential calls than pool_size",
          "[transport][round-trip][bidi][pool]") {
    // Pool size 2; run 6 sequential bidi calls. All must complete
    // because the pool reuses workers — the OS thread budget never
    // exceeds 2 even though 6 calls were dispatched in total.
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, BidiStream& stream) -> Status {
        StringMessage msg;
        while (stream.read(msg)) {
            StringMessage out("echo:" + msg.data());
            if (!stream.write(out)) {
                return Status{StatusCode::Internal, "write failed"};
            }
        }
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/PoolReuse", handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};

    ListenerOptions opts;
    opts.bidi_dispatcher_pool_size = 2;

    REQUIRE(listener->start(bind, creds, opts).has_value());

    auto ch = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    constexpr int N = 6;
    for (int i = 0; i < N; ++i) {
        CallContext ctx;
        ctx.deadline = std::chrono::seconds(5);
        auto stream = ch->bidi_stream("yuzu.test.v1.Echo/PoolReuse", ctx);
        REQUIRE(stream != nullptr);
        StringMessage out("frame_" + std::to_string(i));
        REQUIRE(stream->write(out));
        StringMessage in;
        REQUIRE(stream->read(in));
        REQUIRE(in.data() == "echo:frame_" + std::to_string(i));
        stream->writes_done();
        StringMessage drain;
        REQUIRE_FALSE(stream->read(drain));
        REQUIRE(stream->final_status().code == StatusCode::Ok);
    }

    listener->shutdown();
}

TEST_CASE("Bidi pool rejects overflow with ResourceExhausted",
          "[transport][round-trip][bidi][pool]") {
    // Pool size 1. Hold one bidi call open with a handler that blocks
    // on read until told to release. A second concurrent dispatch must
    // see ResourceExhausted because the single pool slot is occupied.
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    std::mutex release_mtx;
    std::condition_variable release_cv;
    bool release_handler = false;

    auto blocking_handler = [&](const CallContext&, BidiStream& stream) -> Status {
        StringMessage msg;
        // Wait until the test signals release before we exit. While we
        // are waiting, the pool slot stays occupied.
        std::unique_lock<std::mutex> lock(release_mtx);
        release_cv.wait(lock, [&] { return release_handler; });
        // After release, drain any pending reads and exit.
        lock.unlock();
        while (stream.read(msg)) {}
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/PoolBlock", blocking_handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};

    ListenerOptions opts;
    opts.bidi_dispatcher_pool_size = 1;

    REQUIRE(listener->start(bind, creds, opts).has_value());

    auto ch = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    // First call — occupies the single pool slot. Drive it via a
    // concurrent thread so this test thread can issue the second
    // (overflow) call while the first is parked.
    CallContext ctx1;
    ctx1.deadline = std::chrono::seconds(10);
    auto first = ch->bidi_stream("yuzu.test.v1.Echo/PoolBlock", ctx1);
    REQUIRE(first != nullptr);
    StringMessage seed("seed");
    REQUIRE(first->write(seed));
    // Give the server a moment to dispatch the handler onto the pool.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Second call — pool is saturated. Server schedules Finish with
    // ResourceExhausted via the UnaryPendingFinish reaper path.
    CallContext ctx2;
    ctx2.deadline = std::chrono::seconds(5);
    auto second = ch->bidi_stream("yuzu.test.v1.Echo/PoolBlock", ctx2);
    REQUIRE(second != nullptr);
    second->writes_done();
    StringMessage drain;
    REQUIRE_FALSE(second->read(drain));
    Status second_final = second->final_status();
    REQUIRE(second_final.code == StatusCode::ResourceExhausted);
    REQUIRE(second_final.detail.find("saturated") != std::string::npos);

    // Release the first handler so it exits the pool slot. After this
    // a third call must succeed.
    {
        std::lock_guard<std::mutex> lock(release_mtx);
        release_handler = true;
    }
    release_cv.notify_all();
    first->writes_done();
    StringMessage drain1;
    REQUIRE_FALSE(first->read(drain1));
    REQUIRE(first->final_status().code == StatusCode::Ok);

    // Third call — pool slot freed, expect success.
    CallContext ctx3;
    ctx3.deadline = std::chrono::seconds(5);
    auto third = ch->bidi_stream("yuzu.test.v1.Echo/PoolBlock", ctx3);
    REQUIRE(third != nullptr);
    third->writes_done();
    StringMessage drain3;
    REQUIRE_FALSE(third->read(drain3));
    REQUIRE(third->final_status().code == StatusCode::Ok);

    listener->shutdown();
}

TEST_CASE("Bidi pool default size accepts moderate concurrency",
          "[transport][round-trip][bidi][pool]") {
    // Default pool size resolves to clamp(64, hw*8, 4096). Drive 16
    // concurrent bidi streams to exercise the worker pool under
    // realistic concurrency without depending on the exact resolved
    // size. All streams must complete successfully — the pool absorbs
    // them in parallel rather than serialising on a single worker.
    auto listener = make_server_listener(Backend::Grpc);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, BidiStream& stream) -> Status {
        StringMessage msg;
        while (stream.read(msg)) {
            StringMessage out("ack:" + msg.data());
            if (!stream.write(out)) {
                return Status{StatusCode::Internal, "write failed"};
            }
        }
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/PoolFanout", handler);

    Credentials creds{};
    creds.verify_peer = false;
    creds.client_cert_mode = ClientCertMode::None;
    Endpoint bind{"127.0.0.1", 0};
    REQUIRE(listener->start(bind, creds).has_value());

    auto ch = make_channel(Backend::Grpc, listener->bound_endpoint(), creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(2)));

    constexpr int K = 16;
    std::vector<std::thread> drivers;
    std::atomic<int> completed{0};
    drivers.reserve(K);
    for (int i = 0; i < K; ++i) {
        drivers.emplace_back([&, i] {
            CallContext ctx;
            ctx.deadline = std::chrono::seconds(10);
            auto stream = ch->bidi_stream("yuzu.test.v1.Echo/PoolFanout", ctx);
            if (!stream)
                return;
            StringMessage out("frame_" + std::to_string(i));
            if (!stream->write(out))
                return;
            StringMessage in;
            if (!stream->read(in))
                return;
            if (in.data() != "ack:frame_" + std::to_string(i))
                return;
            stream->writes_done();
            StringMessage drain;
            (void)stream->read(drain);
            if (stream->final_status().code == StatusCode::Ok) {
                completed.fetch_add(1, std::memory_order_release);
            }
        });
    }
    for (auto& t : drivers)
        t.join();
    REQUIRE(completed.load(std::memory_order_acquire) == K);

    listener->shutdown();
}
