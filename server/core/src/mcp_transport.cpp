#include "mcp_transport.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>

namespace yuzu::server::mcp::transport {

bool protocol_version_supported(std::string_view version) {
    static constexpr std::array<std::string_view, 2> kSupported{"2025-03-26", "2025-06-18"};
    return std::find(kSupported.begin(), kSupported.end(), version) != kSupported.end();
}

bool origin_allowed(std::string_view origin, const std::vector<std::string>& allowlist) {
    if (origin.empty()) {
        return true;  // absent → allowed (see header rationale)
    }
    // Exact scheme+host+port match, verbatim — never a prefix/suffix heuristic.
    return std::find(allowlist.begin(), allowlist.end(), origin) != allowlist.end();
}

bool accept_wants_sse(std::string_view accept_header) {
    constexpr std::string_view needle = "text/event-stream";
    if (accept_header.size() < needle.size()) {
        return false;
    }
    const auto lower = [](char c) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    };
    for (std::size_t i = 0; i + needle.size() <= accept_header.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (lower(accept_header[i + j]) != needle[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

}  // namespace yuzu::server::mcp::transport
