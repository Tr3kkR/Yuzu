// SPDX-License-Identifier: Apache-2.0
//
// Status::detail sanitiser shared across every transport backend.
//
// Lives in `transport/include/yuzu/transport/detail/` rather than the
// gRPC-private `transport/src/grpc/grpc_internal_helpers.hpp` because the
// scrub is contractually MANDATORY in BOTH directions (outbound + inbound)
// for every implementation — see the Status::detail contract block in
// `transport.hpp`. The msquic backend in PR 3 includes this same header
// so wire-byte semantics stay byte-identical across backends. Promoting
// the helper closes the architectural ambiguity that surfaced as
// governance round 5 finding sec-1 / arch-1 / arch-3 / cons-G4-2.

#pragma once

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu::transport {

// Sanitise a Status::detail string before it crosses the wire (outbound)
// or before surfacing peer-supplied bytes to upper layers (inbound).
//
// Rules (must match across every backend):
//   * Bytes outside the printable ASCII range [0x20, 0x7E] are replaced
//     with '?'. NUL bytes specifically would be silently mangled by gRPC's
//     HTTP/2 trailer encoding (governance UP-22); replacing them here is
//     defensive against that AND against any wire-mangling, log-injection,
//     or downstream-consumer hazard from an arbitrary peer.
//   * The output is capped at exactly kMaxOutBytes total bytes — including
//     any truncation marker. Inputs longer than the payload budget produce
//     a marked truncation suffix that fits inside the 1024-byte cap, so
//     the metadata-trailer budget is never exceeded (governance round 5
//     cpp S1 / UP-46).
//
// Symmetric application is the contract: producers scrub before
// transmission; receivers scrub before any downstream surface (audit log,
// metric label, dashboard render). See transport.hpp Status::detail
// visibility block.
inline std::string sanitise_status_detail(std::string_view in) noexcept {
    // Total cap on bytes the helper will ever emit. A future bump must be
    // matched in transport.hpp's contract block AND in the metadata-trailer
    // budget reasoning of every linked backend.
    constexpr std::size_t kMaxOutBytes = 1024;
    static constexpr std::string_view kSuffix{"...[truncated]"};
    static_assert(kSuffix.size() < kMaxOutBytes,
                  "truncation suffix must fit inside the cap");

    std::string out;
    if (in.size() <= kMaxOutBytes) {
        out.reserve(in.size());
        for (const char c : in) {
            const auto u = static_cast<unsigned char>(c);
            out.push_back((u < 0x20 || u >= 0x7F) ? '?' : c);
        }
        return out;
    }

    // Truncation: payload + suffix together must equal kMaxOutBytes.
    constexpr std::size_t kPayloadBudget = kMaxOutBytes - kSuffix.size();
    out.reserve(kMaxOutBytes);
    for (std::size_t i = 0; i < kPayloadBudget; ++i) {
        const auto u = static_cast<unsigned char>(in[i]);
        out.push_back((u < 0x20 || u >= 0x7F) ? '?' : static_cast<char>(u));
    }
    out.append(kSuffix.data(), kSuffix.size());
    return out;
}

}  // namespace yuzu::transport
