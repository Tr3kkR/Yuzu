// SPDX-License-Identifier: Apache-2.0
// #376 PR 3, increment 1 — unit tests for the QUIC length-prefix framing
// codec.
//
// gRPC inherited message framing from HTTP/2; a raw QUIC stream is a byte
// stream, so the 4-byte-big-endian-length + protobuf framing is new,
// msquic-backend-specific logic. It has zero dependency on the msquic C
// library, so this suite compiles and runs green on any `-Dtransport=`
// configuration — it is the lowest-risk, first-to-land increment.

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>

#include "msquic_framing.hpp"
#include "yuzu/transport/transport.hpp"

using namespace yuzu::transport;
using yuzu::transport::msquic_backend::encode_frame;
using yuzu::transport::msquic_backend::FrameDecoder;

namespace {
// Big-endian length prefix readback for assertions.
std::uint32_t be32(const std::string& s, std::size_t off) {
    return (static_cast<std::uint32_t>(static_cast<unsigned char>(s[off + 0])) << 24) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(s[off + 1])) << 16) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(s[off + 2])) << 8) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(s[off + 3])));
}
} // namespace

TEST_CASE("encode_frame prepends a 4-byte big-endian length", "[transport][msquic][framing]") {
    std::string out;
    REQUIRE(encode_frame("hello", kDefaultMaxFrameSize, out));
    REQUIRE(out.size() == 4 + 5);
    REQUIRE(be32(out, 0) == 5u);
    REQUIRE(out.substr(4) == "hello");
}

TEST_CASE("encode_frame overwrites the output buffer", "[transport][msquic][framing]") {
    std::string out = "stale-contents-that-must-be-cleared";
    REQUIRE(encode_frame("x", kDefaultMaxFrameSize, out));
    REQUIRE(out.size() == 4 + 1);
    REQUIRE(out.substr(4) == "x");
}

TEST_CASE("encode_frame round-trips an empty payload", "[transport][msquic][framing]") {
    std::string out;
    REQUIRE(encode_frame("", kDefaultMaxFrameSize, out));
    REQUIRE(out.size() == 4);
    REQUIRE(be32(out, 0) == 0u);
}

TEST_CASE("encode_frame treats max_frame == 0 as the default cap", "[transport][msquic][framing]") {
    std::string out;
    // A payload well under the 4 MiB default succeeds with max_frame == 0.
    REQUIRE(encode_frame(std::string(1024, 'a'), 0, out));
    REQUIRE(out.size() == 4 + 1024);
}

TEST_CASE("encode_frame rejects an oversize payload", "[transport][msquic][framing]") {
    std::string out;
    REQUIRE_FALSE(encode_frame(std::string(11, 'a'), 10, out));
    // Exactly at the cap is accepted.
    REQUIRE(encode_frame(std::string(10, 'a'), 10, out));
    REQUIRE(out.size() == 4 + 10);
}

TEST_CASE("FrameDecoder decodes a whole frame fed in one chunk", "[transport][msquic][framing]") {
    std::string wire;
    REQUIRE(encode_frame("payload-one", kDefaultMaxFrameSize, wire));

    FrameDecoder dec{kDefaultMaxFrameSize};
    REQUIRE(dec.feed(wire) == StatusCode::Ok);

    auto frame = dec.next_frame();
    REQUIRE(frame.has_value());
    REQUIRE(*frame == "payload-one");
    REQUIRE_FALSE(dec.next_frame().has_value());
    REQUIRE_FALSE(dec.has_pending_partial());
}

TEST_CASE("FrameDecoder assembles a frame fed one byte at a time", "[transport][msquic][framing]") {
    std::string wire;
    REQUIRE(encode_frame("dribble", kDefaultMaxFrameSize, wire));

    FrameDecoder dec{kDefaultMaxFrameSize};
    for (std::size_t i = 0; i + 1 < wire.size(); ++i) {
        REQUIRE(dec.feed(std::string_view{&wire[i], 1}) == StatusCode::Ok);
        // No complete frame until the final byte lands.
        REQUIRE_FALSE(dec.next_frame().has_value());
    }
    REQUIRE(dec.feed(std::string_view{&wire[wire.size() - 1], 1}) == StatusCode::Ok);

    auto frame = dec.next_frame();
    REQUIRE(frame.has_value());
    REQUIRE(*frame == "dribble");
}

TEST_CASE("FrameDecoder splits two concatenated frames in one feed",
          "[transport][msquic][framing]") {
    std::string a, b;
    REQUIRE(encode_frame("first", kDefaultMaxFrameSize, a));
    REQUIRE(encode_frame("second", kDefaultMaxFrameSize, b));

    FrameDecoder dec{kDefaultMaxFrameSize};
    REQUIRE(dec.feed(a + b) == StatusCode::Ok);

    auto f1 = dec.next_frame();
    auto f2 = dec.next_frame();
    REQUIRE(f1.has_value());
    REQUIRE(f2.has_value());
    REQUIRE(*f1 == "first"); // FIFO order preserved
    REQUIRE(*f2 == "second");
    REQUIRE_FALSE(dec.next_frame().has_value());
}

TEST_CASE("FrameDecoder reassembles a length prefix split across feeds",
          "[transport][msquic][framing]") {
    std::string wire;
    REQUIRE(encode_frame("prefix-split", kDefaultMaxFrameSize, wire));

    FrameDecoder dec{kDefaultMaxFrameSize};
    // First two bytes of the 4-byte length prefix arrive alone.
    REQUIRE(dec.feed(wire.substr(0, 2)) == StatusCode::Ok);
    REQUIRE_FALSE(dec.next_frame().has_value());
    REQUIRE(dec.has_pending_partial());
    // The rest arrives.
    REQUIRE(dec.feed(wire.substr(2)) == StatusCode::Ok);

    auto frame = dec.next_frame();
    REQUIRE(frame.has_value());
    REQUIRE(*frame == "prefix-split");
}

TEST_CASE("FrameDecoder rejects an over-cap length prefix without producing a frame",
          "[transport][msquic][framing]") {
    // A length prefix declaring max_frame + 1 must be rejected the instant
    // all 4 length bytes are in hand — before any payload buffer is sized
    // to the attacker-controlled value (transport.hpp wire invariant 1).
    const std::size_t cap = 64;
    std::string evil;
    evil.push_back(0); // 0x00000041 == 65 == cap + 1
    evil.push_back(0);
    evil.push_back(0);
    evil.push_back(static_cast<char>(cap + 1));

    FrameDecoder dec{cap};
    REQUIRE(dec.feed(evil) == StatusCode::ResourceExhausted);
    REQUIRE_FALSE(dec.next_frame().has_value());
}

TEST_CASE("FrameDecoder error state is sticky", "[transport][msquic][framing]") {
    const std::size_t cap = 16;
    std::string evil;
    evil.push_back(0);
    evil.push_back(0);
    evil.push_back(0);
    evil.push_back(static_cast<char>(cap + 1));

    FrameDecoder dec{cap};
    REQUIRE(dec.feed(evil) == StatusCode::ResourceExhausted);
    // Once errored, further feeds keep returning the terminal status and
    // never produce frames — the stream is dead.
    REQUIRE(dec.feed("anything") == StatusCode::ResourceExhausted);
    REQUIRE_FALSE(dec.next_frame().has_value());
}

TEST_CASE("FrameDecoder accepts a frame exactly at the cap", "[transport][msquic][framing]") {
    const std::size_t cap = 128;
    std::string wire;
    REQUIRE(encode_frame(std::string(cap, 'z'), cap, wire));

    FrameDecoder dec{cap};
    REQUIRE(dec.feed(wire) == StatusCode::Ok);
    auto frame = dec.next_frame();
    REQUIRE(frame.has_value());
    REQUIRE(frame->size() == cap);
}

TEST_CASE("FrameDecoder round-trips an empty-payload frame", "[transport][msquic][framing]") {
    std::string wire;
    REQUIRE(encode_frame("", kDefaultMaxFrameSize, wire));

    FrameDecoder dec{kDefaultMaxFrameSize};
    REQUIRE(dec.feed(wire) == StatusCode::Ok);
    auto frame = dec.next_frame();
    REQUIRE(frame.has_value());
    REQUIRE(frame->empty());
}
