// SPDX-License-Identifier: Apache-2.0
// Internal helpers shared between the msquic client and server backends.
//
// Single source of truth for: the process-wide msquic library handle
// (MsQuicApi), QUIC_STATUS -> StatusCode mapping, and QUIC_ADDR
// construction. Re-exports the cross-backend method-name validator and
// Status::detail sanitiser so call sites resolve unqualified, exactly as
// grpc_internal_helpers.hpp does for the gRPC backend.
//
// #376 PR 3, increment 2.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "msquic.h"

#include "yuzu/transport/detail/method_name.hpp"  // method_name_well_formed
#include "yuzu/transport/detail/sanitise.hpp"     // sanitise_status_detail
#include "yuzu/transport/transport.hpp"

namespace yuzu::transport::msquic_backend {

// Re-export the cross-backend helpers into the msquic namespace so call
// sites resolve without qualification — byte-identical semantics to the
// gRPC backend.
using ::yuzu::transport::sanitise_status_detail;
using ::yuzu::transport::detail::method_name_well_formed;

// Process-wide msquic library handle.
//
// MsQuicOpen2 (API table) + RegistrationOpen (the object that owns
// msquic's internal worker threads) are done exactly once. The
// registration outlives every Channel and ServerListener, so it is a
// Meyers singleton — thread-safe first-use init, torn down at process
// exit in the correct order (RegistrationClose then MsQuicClose). All
// listeners/channels/connections/streams must be closed before that
// teardown; in practice they are owned by unique_ptrs in app/test code
// that go out of scope before main() returns.
class MsQuicApi {
public:
    static MsQuicApi& instance();

    MsQuicApi(const MsQuicApi&)            = delete;
    MsQuicApi& operator=(const MsQuicApi&) = delete;

    // True iff MsQuicOpen2 + RegistrationOpen both succeeded. When false,
    // api()/registration() are nullptr and callers surface
    // StatusCode::Internal with init_error() as the detail.
    bool ok() const noexcept {
        return api_ != nullptr && registration_ != nullptr;
    }
    const QUIC_API_TABLE* api() const noexcept { return api_; }
    HQUIC registration() const noexcept { return registration_; }
    const std::string& init_error() const noexcept { return init_error_; }

private:
    MsQuicApi();
    ~MsQuicApi();

    const QUIC_API_TABLE* api_          = nullptr;
    HQUIC                 registration_ = nullptr;
    std::string           init_error_;
};

// Map a QUIC_STATUS to the transport StatusCode taxonomy. QUIC_SUCCEEDED
// values map to Ok; everything else to the closest gRPC-style code.
StatusCode quic_status_to_status_code(QUIC_STATUS status) noexcept;

// Render a QUIC_STATUS as a short hex string for Status::detail.
std::string quic_status_hex(QUIC_STATUS status);

// Fill `out` from a host string + port for a server-side ListenerStart
// bind. `host` may be an IPv4/IPv6 literal or a wildcard ("", "0.0.0.0",
// "::"). DNS names are NOT resolved here — the client side hands
// hostnames straight to msquic's ConnectionStart, which resolves them
// itself. Returns false if `host` is a non-empty, non-wildcard string
// that does not parse as an IP literal.
bool make_quic_addr(std::string_view host, uint16_t port,
                    QUIC_ADDR& out) noexcept;

}  // namespace yuzu::transport::msquic_backend
