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
