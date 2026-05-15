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

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

#include "test_transport_helpers.hpp" // yuzu::transport::test::StringMessage
#include "yuzu/transport/transport.hpp"

#ifdef YUZU_TRANSPORT_HAVE_MSQUIC
#include "msquic_bidi_stream.hpp" // debug:: probes for back-pressure
#include "test_certs.hpp"
#endif

#ifdef YUZU_TRANSPORT_HAVE_MSQUIC
namespace {
// Inc 5: every existing round-trip case uses the test fixture credentials
// (verify_peer = false + ClientCertMode::None — server-auth-only TLS),
// which the new posture gate refuses unless YUZU_ALLOW_INSECURE_TLS=1.
// Set the env var process-wide before any TEST_CASE runs so the existing
// suite keeps passing; the dedicated gate cases below toggle it
// explicitly to verify the rejection path.
struct InsecureTlsEnvSetup {
    InsecureTlsEnvSetup() {
#ifdef _WIN32
        _putenv_s("YUZU_ALLOW_INSECURE_TLS", "1");
#else
        ::setenv("YUZU_ALLOW_INSECURE_TLS", "1", /*overwrite=*/1);
#endif
    }
};
const InsecureTlsEnvSetup g_insecure_tls_env_setup;
} // namespace
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

// ── Bidi round-trip cases (#376 PR 3 increment 3) ────────────────────────────

TEST_CASE("msquic bidi echoes N frames in order", "[transport][msquic][round-trip][bidi]") {
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    // Server reads every inbound frame and echoes it with an "ack:" prefix
    // until the peer half-closes; then returns Ok.
    auto handler = [](const CallContext&, BidiStream& s) -> Status {
        StringMessage in;
        while (s.read(in)) {
            StringMessage out("ack:" + in.data());
            if (!s.write(out)) {
                return Status{StatusCode::Unavailable, "transport: server write failed"};
            }
        }
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/Bidi", handler);

    Credentials creds = make_test_creds();
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    CallContext ctx;
    auto bidi = ch->bidi_stream("yuzu.test.v1.Echo/Bidi", ctx);
    REQUIRE(bidi != nullptr);

    constexpr int N = 5;
    for (int i = 0; i < N; ++i) {
        StringMessage out("frame-" + std::to_string(i));
        REQUIRE(bidi->write(out));
    }
    bidi->writes_done();

    int got = 0;
    StringMessage in;
    while (bidi->read(in)) {
        REQUIRE(in.data() == "ack:frame-" + std::to_string(got));
        ++got;
    }
    REQUIRE(got == N);
    REQUIRE(bidi->final_status().code == StatusCode::Ok);

    ch->close();
    listener->shutdown();
}

TEST_CASE("msquic bidi propagates a handler-returned error status",
          "[transport][msquic][round-trip][bidi]") {
    // governance qe parity — bidi version of the unary handler-error case.
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, BidiStream& s) -> Status {
        StringMessage in;
        s.read(in); // drain at least the first frame so the test's
                    // write actually leaves the client buffer
        return Status{StatusCode::PermissionDenied, "operator denied"};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/BidiDenied", handler);

    Credentials creds = make_test_creds();
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    CallContext ctx;
    auto bidi = ch->bidi_stream("yuzu.test.v1.Echo/BidiDenied", ctx);
    REQUIRE(bidi != nullptr);

    StringMessage out("hello");
    REQUIRE(bidi->write(out));
    bidi->writes_done();

    StringMessage in;
    while (bidi->read(in)) { /* drain — server sends no data frames */
    }

    Status fs = bidi->final_status();
    REQUIRE(fs.code == StatusCode::PermissionDenied);
    REQUIRE(fs.detail == "operator denied");

    ch->close();
    listener->shutdown();
}

TEST_CASE("msquic bidi concurrent reader and writer threads coexist",
          "[transport][msquic][round-trip][bidi]") {
    // transport.hpp BidiStream contract: single-reader + single-writer
    // are concurrent-safe. This test runs them on separate threads on
    // the same MsquicBidiStream and asserts every echoed frame arrives.
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, BidiStream& s) -> Status {
        StringMessage in;
        while (s.read(in)) {
            StringMessage out("ack:" + in.data());
            if (!s.write(out)) {
                return Status{StatusCode::Unavailable, "transport: server write failed"};
            }
        }
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/BidiConcurrent", handler);

    Credentials creds = make_test_creds();
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    CallContext ctx;
    auto bidi = ch->bidi_stream("yuzu.test.v1.Echo/BidiConcurrent", ctx);
    REQUIRE(bidi != nullptr);

    constexpr int N = 10;
    std::atomic<int> received{0};
    std::thread reader([&] {
        StringMessage in;
        while (bidi->read(in)) {
            received.fetch_add(1, std::memory_order_relaxed);
        }
    });
    std::thread writer([&] {
        for (int i = 0; i < N; ++i) {
            StringMessage out("c-" + std::to_string(i));
            (void)bidi->write(out);
        }
        bidi->writes_done();
    });
    writer.join();
    reader.join();

    REQUIRE(received.load(std::memory_order_relaxed) == N);
    REQUIRE(bidi->final_status().code == StatusCode::Ok);

    ch->close();
    listener->shutdown();
}

// ── Back-pressure (#376 PR 3 increment 3.5) ──────────────────────────────────

TEST_CASE("msquic bidi back-pressure pauses receives when inbound queue grows",
          "[transport][msquic][round-trip][bidi][backpressure]") {
    // qe-S3.5: a fast sender + slow reader must not grow inbound_bytes
    // unboundedly. Lower the watermarks so the path engages without
    // streaming megabytes of payload, then assert (1) every frame still
    // arrives, (2) the final status is Ok, (3) StreamReceiveSetEnabled was
    // toggled off and back on at least once each.
    namespace dbg = ::yuzu::transport::msquic_backend::debug;

    dbg::bidi_reset_backpressure_counters();
    dbg::bidi_set_backpressure_thresholds(/*high=*/4 * 1024, /*low=*/1 * 1024);
    // Ensure thresholds are restored even if the test aborts.
    struct ThresholdRestore {
        ~ThresholdRestore() { dbg::bidi_reset_backpressure_thresholds(); }
    } _restore;

    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    constexpr int kFrames = 64;
    constexpr int kFrameSize = 256; // 64 * 256 = 16 KiB, well above 4 KiB

    std::atomic<int> received{0};
    auto handler = [&received](const CallContext&, BidiStream& s) -> Status {
        StringMessage in;
        // Slow drain: 2 ms between reads ensures the sender outpaces us
        // long enough that the buffered payload crosses the high-water
        // mark before we drain it back below the low-water mark.
        while (s.read(in)) {
            received.fetch_add(1, std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/BidiBackpressure", handler);

    Credentials creds = make_test_creds();
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    CallContext ctx;
    auto bidi = ch->bidi_stream("yuzu.test.v1.Echo/BidiBackpressure", ctx);
    REQUIRE(bidi != nullptr);

    const std::string payload(kFrameSize, 'X');
    for (int i = 0; i < kFrames; ++i) {
        StringMessage out(payload);
        REQUIRE(bidi->write(out));
    }
    bidi->writes_done();

    Status fs = bidi->final_status();
    REQUIRE(fs.code == StatusCode::Ok);
    REQUIRE(received.load(std::memory_order_relaxed) == kFrames);

    // The slow handler MUST have caused at least one pause/resume cycle on
    // the server's inbound stream. Both counters are process-global so
    // any spurious increments from prior cases would have been zeroed at
    // the top of this case.
    REQUIRE(dbg::bidi_receive_disabled_count() > 0);
    REQUIRE(dbg::bidi_receive_enabled_count() > 0);

    ch->close();
    listener->shutdown();
}

// ── Deadlines (#376 PR 3 increment 4) ────────────────────────────────────────

TEST_CASE("msquic bidi read deadline expires and reports DeadlineExceeded",
          "[transport][msquic][round-trip][bidi][deadline]") {
    // qe-S4a: read(deadline) on a stream where the peer is silent must
    // wake at the deadline, return false, and final_status() must return
    // DeadlineExceeded — not Cancelled — even though the wire-level
    // shutdown is an ABORT.
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    // Server holds the stream open without writing anything. The handler
    // exits when its own read returns (peer ABORT propagates as false).
    auto handler = [](const CallContext&, BidiStream& s) -> Status {
        StringMessage in;
        while (s.read(in)) { /* no replies */
        }
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/BidiSilent", handler);

    Credentials creds = make_test_creds();
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    CallContext ctx;
    auto bidi = ch->bidi_stream("yuzu.test.v1.Echo/BidiSilent", ctx);
    REQUIRE(bidi != nullptr);

    StringMessage out("hello"), in;
    REQUIRE(bidi->write(out));
    auto t0 = std::chrono::steady_clock::now();
    REQUIRE_FALSE(bidi->read(in, std::chrono::milliseconds(200)));
    auto elapsed = std::chrono::steady_clock::now() - t0;
    REQUIRE(elapsed >= std::chrono::milliseconds(150));
    REQUIRE(elapsed < std::chrono::seconds(2));

    Status fs = bidi->final_status();
    REQUIRE(fs.code == StatusCode::DeadlineExceeded);

    ch->close();
    listener->shutdown();
}

TEST_CASE("msquic bidi read negative deadline is clamped (no immediate timeout)",
          "[transport][msquic][round-trip][bidi][deadline]") {
    // qe-S4b / arch-S1 / #915: a negative deadline must be treated as
    // zero ("no deadline") — NOT as "expire immediately". Pass -1 ms
    // and verify the read still receives the frame the server sends.
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, BidiStream& s) -> Status {
        StringMessage in;
        if (!s.read(in))
            return Status{StatusCode::Ok, ""};
        StringMessage out("ack:" + in.data());
        s.write(out);
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/BidiNegDeadline", handler);

    Credentials creds = make_test_creds();
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    CallContext ctx;
    auto bidi = ch->bidi_stream("yuzu.test.v1.Echo/BidiNegDeadline", ctx);
    REQUIRE(bidi != nullptr);

    StringMessage out("hi"), in;
    REQUIRE(bidi->write(out, std::chrono::milliseconds(-5)));
    bidi->writes_done();
    REQUIRE(bidi->read(in, std::chrono::milliseconds(-5)));
    REQUIRE(in.data() == "ack:hi");
    REQUIRE(bidi->final_status().code == StatusCode::Ok);

    ch->close();
    listener->shutdown();
}

TEST_CASE("msquic bidi write deadline does not fire on a prompt peer",
          "[transport][msquic][round-trip][bidi][deadline]") {
    // qe-S4c: a positive write deadline against a healthy peer is a
    // no-op (StreamSend accepts immediately). Verify the write succeeds
    // and the round trip completes without spurious DeadlineExceeded.
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, BidiStream& s) -> Status {
        StringMessage in;
        while (s.read(in)) {
            StringMessage out("ack:" + in.data());
            (void)s.write(out);
        }
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/BidiWriteDeadline", handler);

    Credentials creds = make_test_creds();
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    CallContext ctx;
    auto bidi = ch->bidi_stream("yuzu.test.v1.Echo/BidiWriteDeadline", ctx);
    REQUIRE(bidi != nullptr);

    StringMessage out("ping"), in;
    REQUIRE(bidi->write(out, std::chrono::milliseconds(500)));
    bidi->writes_done();
    REQUIRE(bidi->read(in, std::chrono::seconds(2)));
    REQUIRE(in.data() == "ack:ping");
    REQUIRE(bidi->final_status().code == StatusCode::Ok);

    ch->close();
    listener->shutdown();
}

TEST_CASE("msquic unary CallContext::deadline expires client-side on slow handler",
          "[transport][msquic][round-trip][deadline]") {
    // qe-S4d: an unbounded handler causes the client to wake at
    // ctx.deadline with DeadlineExceeded — the 10 s safety net does
    // NOT win when the operator provided a tighter deadline.
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, const SerializableMessage&,
                      SerializableMessage&) -> Status {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return Status{StatusCode::Ok, ""};
    };
    listener->register_unary("yuzu.test.v1.Echo/Slow", string_factory, string_factory, handler);

    Credentials creds = make_test_creds();
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    StringMessage req("hi"), resp;
    CallContext ctx;
    ctx.deadline = std::chrono::milliseconds(200);
    auto t0 = std::chrono::steady_clock::now();
    auto r = ch->unary("yuzu.test.v1.Echo/Slow", ctx, req, resp);
    auto elapsed = std::chrono::steady_clock::now() - t0;
    REQUIRE(r.status.code == StatusCode::DeadlineExceeded);
    REQUIRE(elapsed < std::chrono::seconds(1));

    ch->close();
    listener->shutdown();
}

// (server-side "already-expired before dispatch" rejection IS implemented
//  in msquic_listener.cpp's HandshakeHello path, but is not directly
//  tested here: on loopback the handler can return faster than 1 ms, so
//  any "client sets a 1 ms deadline + sleeps before unary()" formulation
//  races and produces a flaky `Ok` instead of `DeadlineExceeded`. The
//  client-side timeout test above covers the user-visible contract; the
//  server-side optimisation is exercised when deadline_unix_millis lands
//  in the past for any reason — clock skew, queueing, or client-side
//  scheduling delay.)

// ── TLS posture + ALPN (#376 PR 3 increment 5a) ──────────────────────────────

TEST_CASE("msquic insecure credentials are refused without YUZU_ALLOW_INSECURE_TLS",
          "[transport][msquic][round-trip][tls][posture]") {
    // qe-S5a / sec invariant: the gate refuses verify_peer=false on the
    // client and ClientCertMode::None on the server unless the env var
    // is explicitly set to "1". Any other value (unset, "0", "true")
    // rejects.
#ifdef _WIN32
    _putenv_s("YUZU_ALLOW_INSECURE_TLS", "");
#else
    ::unsetenv("YUZU_ALLOW_INSECURE_TLS");
#endif
    struct EnvRestore {
        ~EnvRestore() {
#ifdef _WIN32
            _putenv_s("YUZU_ALLOW_INSECURE_TLS", "1");
#else
            ::setenv("YUZU_ALLOW_INSECURE_TLS", "1", /*overwrite=*/1);
#endif
        }
    } _restore;

    // Server side: ClientCertMode::None refused.
    {
        auto listener = make_server_listener(Backend::Msquic);
        REQUIRE(listener != nullptr);
        Credentials creds = make_test_creds(); // verify_peer=false + None
        auto r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == StatusCode::FailedPrecondition);
        REQUIRE(r.error().detail.find("YUZU_ALLOW_INSECURE_TLS") != std::string::npos);
    }

    // Client side: verify_peer=false refused at first connect attempt.
    {
        Credentials creds = make_test_creds(); // verify_peer=false
        auto ch = make_channel(Backend::Msquic, Endpoint{"127.0.0.1", 1}, creds);
        REQUIRE(ch != nullptr);
        REQUIRE_FALSE(ch->wait_for_connected(std::chrono::milliseconds(100)));
        // Issue a no-op unary to surface the FailedPrecondition (the
        // channel returns this for every call until creds are reloaded).
        StringMessage req("x"), resp;
        CallContext ctx;
        auto r = ch->unary("yuzu.test.v1.Echo/X", ctx, req, resp);
        REQUIRE(r.status.code == StatusCode::FailedPrecondition);
    }
}

TEST_CASE("msquic ALPN mismatch surfaces as Unavailable on the client",
          "[transport][msquic][round-trip][tls][alpn]") {
    // qe-S5b: client offers an ALPN the server does not advertise; the
    // QUIC handshake fails before any RPC. The msquic backend maps
    // QUIC_STATUS_ALPN_NEG_FAILURE to StatusCode::Unavailable
    // (msquic_internal_helpers.cpp).
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    Credentials server_creds = make_test_creds();
    server_creds.alpn_protocols = {"yuzu/1"};
    auto handler = [](const CallContext&, const SerializableMessage&,
                      SerializableMessage&) -> Status {
        return Status{StatusCode::Ok, ""};
    };
    listener->register_unary("yuzu.test.v1.Echo/Echo", string_factory, string_factory, handler);
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, server_creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    Credentials client_creds = make_test_creds();
    client_creds.alpn_protocols = {"yuzu/never-spoken-here"};
    auto ch = make_channel(Backend::Msquic, bound, client_creds);
    REQUIRE(ch != nullptr);

    StringMessage req("x"), resp;
    CallContext ctx;
    auto r = ch->unary("yuzu.test.v1.Echo/Echo", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Unavailable);

    ch->close();
    listener->shutdown();
}

TEST_CASE("msquic ALPN multi-protocol negotiation picks a common entry",
          "[transport][msquic][round-trip][tls][alpn]") {
    // qe-S5c: server offers {"yuzu/1", "yuzu-test"}, client offers
    // {"yuzu-test"}. Handshake succeeds; the round trip completes.
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    Credentials server_creds = make_test_creds();
    server_creds.alpn_protocols = {"yuzu/1", "yuzu-test"};
    auto handler = [](const CallContext&, const SerializableMessage& req,
                      SerializableMessage& resp) -> Status {
        const auto& sreq = static_cast<const StringMessage&>(req);
        auto& sresp = static_cast<StringMessage&>(resp);
        sresp.set_data("ack:" + sreq.data());
        return Status{StatusCode::Ok, ""};
    };
    listener->register_unary("yuzu.test.v1.Echo/Echo", string_factory, string_factory, handler);
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, server_creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    Credentials client_creds = make_test_creds();
    client_creds.alpn_protocols = {"yuzu-test"};
    auto ch = make_channel(Backend::Msquic, bound, client_creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    StringMessage req("hi"), resp;
    CallContext ctx;
    auto r = ch->unary("yuzu.test.v1.Echo/Echo", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Ok);
    REQUIRE(resp.data() == "ack:hi");

    ch->close();
    listener->shutdown();
}

// ── Metric sink parity (#376 PR 3 increment 6) ───────────────────────────────

#ifdef YUZU_TRANSPORT_HAVE_MSQUIC
namespace {

struct RecordingMetricSink final : public TransportMetricSink {
    struct Event {
        std::string kind;    // "conn_opened" / "stream_opened" / etc.
        std::string backend; // always "msquic"
        std::string method;  // method name when applicable, else ""
        std::size_t bytes = 0;
        Status final_status{};
    };

    mutable std::mutex mtx;
    std::vector<Event> events;

    void on_connection_opened(std::string_view backend) override {
        std::lock_guard<std::mutex> lock(mtx);
        events.push_back({"conn_opened", std::string(backend), "", 0, {}});
    }
    void on_connection_closed(std::string_view backend, Status final) override {
        std::lock_guard<std::mutex> lock(mtx);
        events.push_back({"conn_closed", std::string(backend), "", 0, final});
    }
    void on_stream_opened(std::string_view backend, std::string_view method) override {
        std::lock_guard<std::mutex> lock(mtx);
        events.push_back({"stream_opened", std::string(backend), std::string(method), 0, {}});
    }
    void on_stream_closed(std::string_view backend, std::string_view method,
                          Status final) override {
        std::lock_guard<std::mutex> lock(mtx);
        events.push_back({"stream_closed", std::string(backend), std::string(method), 0, final});
    }
    void on_bytes_sent(std::string_view backend, std::size_t bytes) override {
        std::lock_guard<std::mutex> lock(mtx);
        events.push_back({"bytes_sent", std::string(backend), "", bytes, {}});
    }
    void on_bytes_received(std::string_view backend, std::size_t bytes) override {
        std::lock_guard<std::mutex> lock(mtx);
        events.push_back({"bytes_received", std::string(backend), "", bytes, {}});
    }
    void on_unexpected_dispatch_throw(std::string_view backend, std::string_view method,
                                      std::string_view kind) override {
        std::lock_guard<std::mutex> lock(mtx);
        events.push_back({"dispatch_throw_" + std::string(kind),
                          std::string(backend),
                          std::string(method),
                          0,
                          {}});
    }

    bool has(const std::string& kind) const {
        std::lock_guard<std::mutex> lock(mtx);
        for (const auto& e : events) {
            if (e.kind == kind)
                return true;
        }
        return false;
    }
    bool has_with_method(const std::string& kind, const std::string& method) const {
        std::lock_guard<std::mutex> lock(mtx);
        for (const auto& e : events) {
            if (e.kind == kind && e.method == method)
                return true;
        }
        return false;
    }
    std::size_t total_bytes(const std::string& kind) const {
        std::lock_guard<std::mutex> lock(mtx);
        std::size_t sum = 0;
        for (const auto& e : events) {
            if (e.kind == kind)
                sum += e.bytes;
        }
        return sum;
    }
};

} // namespace
#endif

TEST_CASE("msquic metric sink fires connection + stream + bytes events with msquic backend label",
          "[transport][msquic][round-trip][metrics]") {
    // qe-S6: A round-trip with a recording sink installed on both sides
    // must produce on_connection_opened/closed, on_stream_opened/closed,
    // and on_bytes_sent/received events all labelled "msquic". The
    // method label on stream_opened/closed must match the registered
    // method exactly.
    auto server_sink = std::make_shared<RecordingMetricSink>();
    auto client_sink = std::make_shared<RecordingMetricSink>();

    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);
    auto handler = [](const CallContext&, const SerializableMessage& req,
                      SerializableMessage& resp) -> Status {
        const auto& sreq = static_cast<const StringMessage&>(req);
        auto& sresp = static_cast<StringMessage&>(resp);
        sresp.set_data("ack:" + sreq.data());
        return Status{StatusCode::Ok, ""};
    };
    listener->register_unary("yuzu.test.v1.Echo/Echo", string_factory, string_factory, handler);

    Credentials creds = make_test_creds();
    ListenerOptions opts;
    opts.metric_sink = server_sink;
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds, opts);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Msquic, bound, creds, BackoffPolicy{}, client_sink);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    StringMessage req("hi"), resp;
    CallContext ctx;
    auto r = ch->unary("yuzu.test.v1.Echo/Echo", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Ok);
    REQUIRE(resp.data() == "ack:hi");

    ch->close();
    listener->shutdown();

    REQUIRE(client_sink->has("conn_opened"));
    REQUIRE(server_sink->has("conn_opened"));
    REQUIRE(client_sink->has_with_method("stream_opened", "yuzu.test.v1.Echo/Echo"));
    REQUIRE(server_sink->has_with_method("stream_opened", "yuzu.test.v1.Echo/Echo"));
    REQUIRE(client_sink->has_with_method("stream_closed", "yuzu.test.v1.Echo/Echo"));
    REQUIRE(server_sink->has_with_method("stream_closed", "yuzu.test.v1.Echo/Echo"));
    REQUIRE(client_sink->total_bytes("bytes_sent") > 0);
    REQUIRE(client_sink->total_bytes("bytes_received") > 0);
    REQUIRE(server_sink->total_bytes("bytes_sent") > 0);
    REQUIRE(server_sink->total_bytes("bytes_received") > 0);
}

TEST_CASE("msquic metric sink fires on_unexpected_dispatch_throw on a thrown handler",
          "[transport][msquic][round-trip][metrics]") {
    // qe-S6b: a handler that throws std::exception must trigger
    // on_unexpected_dispatch_throw("msquic", method, "std_exception")
    // on the server-side sink — the kind label is bounded so it is
    // safe as a Prometheus label.
    auto server_sink = std::make_shared<RecordingMetricSink>();

    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);
    auto handler = [](const CallContext&, const SerializableMessage&,
                      SerializableMessage&) -> Status {
        throw std::runtime_error("metric throw test");
    };
    listener->register_unary("yuzu.test.v1.Echo/Throws", string_factory, string_factory, handler);

    Credentials creds = make_test_creds();
    ListenerOptions opts;
    opts.metric_sink = server_sink;
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds, opts);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    StringMessage req("x"), resp;
    CallContext ctx;
    auto r = ch->unary("yuzu.test.v1.Echo/Throws", ctx, req, resp);
    REQUIRE(r.status.code == StatusCode::Internal);

    ch->close();
    listener->shutdown();

    REQUIRE(
        server_sink->has_with_method("dispatch_throw_std_exception", "yuzu.test.v1.Echo/Throws"));
}

TEST_CASE("msquic bidi stream destroyed without final_status terminates cleanly",
          "[transport][msquic][round-trip][bidi]") {
    // transport.hpp: "destroying the BidiStream cancels the stream if
    // not finished." The dtor must not hang or crash — and the listener
    // must be able to shutdown() (which drains live connections) without
    // waiting forever for the abandoned stream.
    auto listener = make_server_listener(Backend::Msquic);
    REQUIRE(listener != nullptr);

    auto handler = [](const CallContext&, BidiStream& s) -> Status {
        StringMessage in;
        while (s.read(in)) { /* discard */
        }
        return Status{StatusCode::Ok, ""};
    };
    listener->register_bidi_stream("yuzu.test.v1.Echo/BidiDestroy", handler);

    Credentials creds = make_test_creds();
    auto start_r = listener->start(Endpoint{"127.0.0.1", 0}, creds);
    REQUIRE(start_r.has_value());
    Endpoint bound = listener->bound_endpoint();

    auto ch = make_channel(Backend::Msquic, bound, creds);
    REQUIRE(ch != nullptr);
    REQUIRE(ch->wait_for_connected(std::chrono::seconds(5)));

    CallContext ctx;
    {
        auto bidi = ch->bidi_stream("yuzu.test.v1.Echo/BidiDestroy", ctx);
        REQUIRE(bidi != nullptr);
        StringMessage out("x");
        (void)bidi->write(out);
        // Drop the unique_ptr without calling writes_done() or
        // final_status() — dtor must cancel cleanly.
    }

    ch->close();
    listener->shutdown(); // must not hang
}

#else // !YUZU_TRANSPORT_HAVE_MSQUIC

TEST_CASE("msquic backend not linked into this build", "[transport][msquic][round-trip]") {
    // -Dtransport=grpc: the msquic factory returns nullptr. The framing
    // codec suite still runs (it has no msquic dependency).
    auto ch = make_channel(Backend::Msquic, Endpoint{"127.0.0.1", 0}, Credentials{});
    REQUIRE(ch == nullptr);
}

#endif // YUZU_TRANSPORT_HAVE_MSQUIC
