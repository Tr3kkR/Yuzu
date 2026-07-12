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
    // Parse the Accept header as a comma-separated list of media ranges and look
    // for `text/event-stream` as a WHOLE media type — never a bare substring.
    // A substring scan false-positives on `application/json; q=text/event-stream`
    // (the token appears in a parameter value) and `not-text/event-stream`
    // (a prefix), so each range is split off, its `;`-delimited parameters are
    // dropped, OWS is trimmed, and the remaining media type is compared exactly
    // (case-insensitive per RFC 9110 — media types are case-insensitive).
    // Limitation (acceptable while this has no production caller — SSE gating is
    // 2f PR 2/3): the split is naive over `,` and does NOT honour RFC 9110
    // quoted-strings, so a `,` inside a quoted parameter value (e.g.
    // `application/json;x=",text/event-stream,"`) could mis-split into a false
    // match. Harden with quoted-string-aware tokenisation before the GET/SSE
    // channel branches on this (tracked follow-up).
    // Wildcards (`*/*`, `text/*`) deliberately do NOT match — SSE requires an
    // explicit `text/event-stream` opt-in, so this fails closed to JSON.
    constexpr std::string_view needle = "text/event-stream";
    const auto lower = [](char c) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    };
    std::size_t pos = 0;
    while (pos <= accept_header.size()) {
        const std::size_t comma = accept_header.find(',', pos);
        std::string_view token =
            accept_header.substr(pos, comma == std::string_view::npos ? std::string_view::npos
                                                                      : comma - pos);
        // Drop any `;`-delimited parameters (q=, charset, etc.) — only the type matters.
        if (const std::size_t semi = token.find(';'); semi != std::string_view::npos) {
            token = token.substr(0, semi);
        }
        // Trim optional leading/trailing whitespace (OWS).
        std::size_t b = 0, e = token.size();
        while (b < e && std::isspace(static_cast<unsigned char>(token[b]))) ++b;
        while (e > b && std::isspace(static_cast<unsigned char>(token[e - 1]))) --e;
        token = token.substr(b, e - b);
        if (token.size() == needle.size()) {
            bool match = true;
            for (std::size_t j = 0; j < needle.size(); ++j) {
                if (lower(token[j]) != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        if (comma == std::string_view::npos) {
            break;
        }
        pos = comma + 1;
    }
    return false;
}

}  // namespace yuzu::server::mcp::transport
