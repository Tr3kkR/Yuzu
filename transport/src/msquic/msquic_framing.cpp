// SPDX-License-Identifier: Apache-2.0
// #376 PR 3, increment 1 — QUIC length-prefix framing codec.

#include "msquic_framing.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::transport::msquic_backend {

namespace {

// Read a 4-byte big-endian length at buffer offset `off`. The caller
// guarantees `s.size() - off >= 4`. Explicit unsigned-char casts + shifts
// rather than ntohl — portable across the compiler matrix and free of
// platform byte-order headers.
std::uint32_t read_be32(const std::string& s, std::size_t off) noexcept {
    return (static_cast<std::uint32_t>(static_cast<unsigned char>(s[off + 0])) << 24) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(s[off + 1])) << 16) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(s[off + 2])) << 8) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(s[off + 3])));
}

}  // namespace

bool encode_frame(std::string_view payload, std::size_t max_frame,
                  std::string& out) {
    const std::size_t cap = max_frame ? max_frame : kDefaultMaxFrameSize;
    if (payload.size() > cap) return false;

    // cap <= kAbsoluteMaxFrameSize (64 MiB) << 2^32, so the narrowing to
    // uint32 for the length prefix cannot truncate.
    const auto len = static_cast<std::uint32_t>(payload.size());
    out.clear();
    out.reserve(4 + payload.size());
    out.push_back(static_cast<char>((len >> 24) & 0xFF));
    out.push_back(static_cast<char>((len >> 16) & 0xFF));
    out.push_back(static_cast<char>((len >> 8) & 0xFF));
    out.push_back(static_cast<char>(len & 0xFF));
    out.append(payload.data(), payload.size());
    return true;
}

StatusCode FrameDecoder::feed(std::string_view bytes) {
    if (error_ != StatusCode::Ok) return error_;

    buffer_.append(bytes.data(), bytes.size());

    std::size_t pos = 0;
    while (buffer_.size() - pos >= 4) {
        const std::uint32_t len = read_be32(buffer_, pos);

        // Frame-size enforcement BEFORE allocating a payload buffer sized
        // to the peer-controlled length (transport.hpp wire invariant 1).
        if (len > max_frame_) {
            error_ = StatusCode::ResourceExhausted;
            buffer_.clear();
            return error_;
        }

        // Payload not fully arrived yet — keep the bytes buffered.
        if (buffer_.size() - pos < 4 + static_cast<std::size_t>(len)) break;

        ready_.emplace_back(buffer_, pos + 4, len);
        pos += 4 + len;
    }

    // Compact consumed bytes once per feed rather than per frame.
    if (pos > 0) buffer_.erase(0, pos);
    return StatusCode::Ok;
}

std::optional<std::string> FrameDecoder::next_frame() {
    if (ready_.empty()) return std::nullopt;
    std::string frame = std::move(ready_.front());
    ready_.pop_front();
    return frame;
}

}  // namespace yuzu::transport::msquic_backend
