// SPDX-License-Identifier: Apache-2.0
// #376 PR 3, increment 2 — msquic backend internal helpers.

#include "msquic_internal_helpers.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <spdlog/spdlog.h>

namespace yuzu::transport::msquic_backend {

// ── MsQuicApi singleton ──────────────────────────────────────────────────────

MsQuicApi::MsQuicApi() {
    QUIC_STATUS st = MsQuicOpen2(&api_);
    if (QUIC_FAILED(st)) {
        init_error_ = "MsQuicOpen2 failed: " + quic_status_hex(st);
        api_ = nullptr;
        // Log at init time, not just when a later caller queries ok():
        // a poisoned singleton otherwise fails silently at startup and
        // only surfaces from unrelated call sites (governance sre-1).
        spdlog::critical("yuzu::transport[msquic]: {}", init_error_);
        return;
    }

    // "yuzu" registration, low-latency execution profile (the agent and
    // server are latency-sensitive control planes, not bulk-throughput).
    const QUIC_REGISTRATION_CONFIG reg_config = {
        "yuzu", QUIC_EXECUTION_PROFILE_LOW_LATENCY};
    st = api_->RegistrationOpen(&reg_config, &registration_);
    if (QUIC_FAILED(st)) {
        init_error_ = "RegistrationOpen failed: " + quic_status_hex(st);
        MsQuicClose(api_);
        api_          = nullptr;
        registration_ = nullptr;
        spdlog::critical("yuzu::transport[msquic]: {}", init_error_);
        return;
    }
}

MsQuicApi::~MsQuicApi() {
    // Deliberately leak the msquic registration + API table at process
    // exit. RegistrationClose blocks the calling thread until every
    // msquic worker has drained outstanding per-connection grace work
    // — even after every Channel and ServerListener has cleanly closed,
    // that drain has been observed to take many tens of seconds (the
    // transport meson test suite hangs the full 180s timeout in this
    // dtor while the test cases themselves complete in <2s).
    //
    // This is a process-lifetime singleton — its dtor runs in static-
    // destruction time, immediately before the OS reclaims the process.
    // Leaking the registration here is harmless: the OS releases the
    // memory and sockets unconditionally on exit. Long-lived production
    // processes (server, agent) never destroy this singleton in normal
    // operation either.
    //
    // Tracked as a follow-up: msquic RegistrationClose process-exit
    // drain (#376 PR 3 increment 3 follow-up).
    registration_ = nullptr;
    api_          = nullptr;
}

MsQuicApi& MsQuicApi::instance() {
    static MsQuicApi inst;
    return inst;
}

// ── Status mapping ───────────────────────────────────────────────────────────

StatusCode quic_status_to_status_code(QUIC_STATUS status) noexcept {
    if (QUIC_SUCCEEDED(status)) return StatusCode::Ok;

    // msquic guarantees a portable logical status set across platforms
    // even though the underlying integer values differ (errno-like on
    // POSIX, HRESULT on Windows) — compare against the QUIC_STATUS_*
    // macros, never raw integers.
    if (status == QUIC_STATUS_INVALID_PARAMETER) return StatusCode::InvalidArgument;
    if (status == QUIC_STATUS_INVALID_ADDRESS)   return StatusCode::InvalidArgument;
    if (status == QUIC_STATUS_INVALID_STATE)     return StatusCode::FailedPrecondition;
    if (status == QUIC_STATUS_NOT_SUPPORTED)     return StatusCode::Unimplemented;
    if (status == QUIC_STATUS_NOT_FOUND)         return StatusCode::NotFound;
    if (status == QUIC_STATUS_BUFFER_TOO_SMALL)  return StatusCode::ResourceExhausted;
    if (status == QUIC_STATUS_OUT_OF_MEMORY)     return StatusCode::ResourceExhausted;
    if (status == QUIC_STATUS_STREAM_LIMIT_REACHED) return StatusCode::ResourceExhausted;
    if (status == QUIC_STATUS_ABORTED)           return StatusCode::Cancelled;
    if (status == QUIC_STATUS_USER_CANCELED)     return StatusCode::Cancelled;
    if (status == QUIC_STATUS_CONNECTION_TIMEOUT) return StatusCode::DeadlineExceeded;
    if (status == QUIC_STATUS_CONNECTION_IDLE)   return StatusCode::DeadlineExceeded;
    if (status == QUIC_STATUS_CONNECTION_REFUSED) return StatusCode::Unavailable;
    if (status == QUIC_STATUS_UNREACHABLE)       return StatusCode::Unavailable;
    if (status == QUIC_STATUS_ADDRESS_IN_USE)    return StatusCode::Unavailable;
    if (status == QUIC_STATUS_ADDRESS_NOT_AVAILABLE) return StatusCode::Unavailable;
    if (status == QUIC_STATUS_ALPN_NEG_FAILURE)  return StatusCode::Unavailable;
    if (status == QUIC_STATUS_VER_NEG_ERROR)     return StatusCode::Unavailable;
    if (status == QUIC_STATUS_ALPN_IN_USE)       return StatusCode::FailedPrecondition;
    if (status == QUIC_STATUS_HANDSHAKE_FAILURE) return StatusCode::Unauthenticated;
    if (status == QUIC_STATUS_TLS_ERROR)         return StatusCode::Unauthenticated;
    if (status == QUIC_STATUS_BAD_CERTIFICATE)   return StatusCode::Unauthenticated;
    if (status == QUIC_STATUS_CERT_EXPIRED)      return StatusCode::Unauthenticated;
    if (status == QUIC_STATUS_EXPIRED_CERTIFICATE) return StatusCode::Unauthenticated;
    if (status == QUIC_STATUS_CERT_UNTRUSTED_ROOT) return StatusCode::Unauthenticated;
    if (status == QUIC_STATUS_REVOKED_CERTIFICATE) return StatusCode::Unauthenticated;
    if (status == QUIC_STATUS_UNKNOWN_CERTIFICATE) return StatusCode::Unauthenticated;
    if (status == QUIC_STATUS_UNSUPPORTED_CERTIFICATE) return StatusCode::Unauthenticated;
    if (status == QUIC_STATUS_REQUIRED_CERTIFICATE) return StatusCode::Unauthenticated;
    if (status == QUIC_STATUS_CERT_NO_CERT)      return StatusCode::Unauthenticated;
    if (status == QUIC_STATUS_PROTOCOL_ERROR)    return StatusCode::Internal;
    if (status == QUIC_STATUS_INTERNAL_ERROR)    return StatusCode::Internal;
    return StatusCode::Unknown;
}

std::string quic_status_hex(QUIC_STATUS status) {
    // QUIC_STATUS is an unsigned integer on every supported platform.
    char buf[2 + sizeof(unsigned long long) * 2 + 1];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(status));
    return std::string(buf);
}

// ── QUIC_ADDR construction ───────────────────────────────────────────────────

bool make_quic_addr(std::string_view host, uint16_t port,
                    QUIC_ADDR& out) noexcept {
    std::memset(&out, 0, sizeof(out));

    const bool wildcard_v4 = host.empty() || host == "0.0.0.0";
    const bool wildcard_v6 = host == "::";

    if (wildcard_v4) {
        QuicAddrSetFamily(&out, QUIC_ADDRESS_FAMILY_INET);
        QuicAddrSetPort(&out, port);
        return true;  // zeroed sin_addr == INADDR_ANY
    }
    if (wildcard_v6) {
        QuicAddrSetFamily(&out, QUIC_ADDRESS_FAMILY_INET6);
        QuicAddrSetPort(&out, port);
        return true;  // zeroed sin6_addr == in6addr_any
    }

    // IP literal. A ':' means IPv6 (no DNS names reach this path).
    const std::string host_str(host);
    if (host.find(':') != std::string_view::npos) {
        if (inet_pton(AF_INET6, host_str.c_str(), &out.Ipv6.sin6_addr) != 1) {
            return false;
        }
        QuicAddrSetFamily(&out, QUIC_ADDRESS_FAMILY_INET6);
        QuicAddrSetPort(&out, port);
        return true;
    }
    if (inet_pton(AF_INET, host_str.c_str(), &out.Ipv4.sin_addr) != 1) {
        return false;
    }
    QuicAddrSetFamily(&out, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&out, port);
    return true;
}

// ── Insecure-TLS posture gate ────────────────────────────────────────────────

namespace {

bool insecure_tls_env_authorized() noexcept {
    const char* v = std::getenv("YUZU_ALLOW_INSECURE_TLS");
    if (v == nullptr) return false;
    return std::string_view{v} == "1";
}

}  // namespace

Status check_insecure_tls_posture(const Credentials& creds,
                                  bool role_is_client) noexcept {
    bool insecure = false;
    if (role_is_client) {
        insecure = !creds.verify_peer;
    } else {
        // Server-side: either verify_peer=false OR ClientCertMode::None
        // is an insecure posture relative to the documented default.
        insecure = !creds.verify_peer ||
                   creds.client_cert_mode == ClientCertMode::None;
    }
    if (!insecure) return Status{};

    // Insecure material observed — log regardless of whether the gate
    // accepts it (per transport.hpp Credentials contract).
    spdlog::warn(
        "yuzu::transport[msquic]: insecure TLS material observed "
        "(role={}, verify_peer={}, client_cert_mode={})",
        role_is_client ? "client" : "server",
        creds.verify_peer,
        static_cast<int>(creds.client_cert_mode));

    if (insecure_tls_env_authorized()) {
        return Status{};
    }
    return Status{
        StatusCode::FailedPrecondition,
        "transport: insecure TLS material refused; set "
        "YUZU_ALLOW_INSECURE_TLS=1 in the environment to override "
        "(see transport.hpp Credentials contract)"};
}

// ── ALPN buffer construction ─────────────────────────────────────────────────

AlpnBuffers build_alpn_buffers(std::vector<std::string> alpn_protocols) {
    AlpnBuffers out;
    out.backing = std::move(alpn_protocols);
    if (out.backing.empty()) {
        out.backing.emplace_back("yuzu/1");
    }
    out.buffers.reserve(out.backing.size());
    for (auto& s : out.backing) {
        QUIC_BUFFER b{};
        b.Length = static_cast<uint32_t>(s.size());
        b.Buffer = reinterpret_cast<uint8_t*>(s.data());
        out.buffers.push_back(b);
    }
    return out;
}

}  // namespace yuzu::transport::msquic_backend
