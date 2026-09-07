#pragma once

/// @file log_safe.hpp
/// `log_safe` — sanitize an operator-supplied value (definition id, approval
/// id) before it goes into a server log line. Control characters — CR/LF
/// especially — would otherwise let a caller forge additional log lines
/// (Gate 8 LOW). Truncates for good measure; callers already substr to
/// bound length.
///
/// Promoted out of `ServerImpl`'s private `static std::string log_safe(...)`
/// (#2542 PR-9) — mirrors `json_extract.hpp`'s (#2557) move: a byte-identical
/// behavior copy, not a rewrite. Promotion, not duplication, because this
/// helper has TWO live callers after PR-9's extraction: the new
/// `approval_routes.cpp` (`register_approval_routes`'s approve/reject
/// handlers) and code that stays inline in `server.cpp` (the instruction
/// YAML update/create handlers, ~lines 17198/17227 as of this writing) — an
/// anonymous-namespace copy in `approval_routes.cpp` would silently diverge
/// from the version `server.cpp` still calls, the exact failure mode
/// `json_extract.hpp`'s header comment warns about.
///
/// Header-only `inline` free function in `namespace yuzu::server`, matching
/// the convention of `dispatch_target_shape.hpp` / `json_extract.hpp` in
/// this directory. `server.cpp`'s `ServerImpl` lives in `namespace
/// yuzu::server`, so its existing unqualified `log_safe(...)` call sites
/// resolve to this via ordinary unqualified lookup — no call site needed to
/// change.

#include <algorithm>
#include <cstddef>
#include <string>

namespace yuzu::server {

[[nodiscard]] inline std::string log_safe(const std::string& s, std::size_t max = 64) {
    std::string out;
    out.reserve(std::min(s.size(), max));
    for (std::size_t i = 0; i < s.size() && i < max; ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        out += (c < 0x20 || c == 0x7f) ? '?' : s[i];
    }
    return out;
}

} // namespace yuzu::server
