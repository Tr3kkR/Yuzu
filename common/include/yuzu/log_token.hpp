#pragma once

/**
 * log_token.hpp - neutralise an untrusted identifier before it is embedded in a
 * space-delimited `key=value` log line (CWE-117 log forging).
 *
 * A raw identifier that contains a newline forges a whole physical log line; one that
 * contains a space or '=' forges extra `key=value` tokens on the SAME line, which a
 * first-match parser then reads. Both are reachable from operator-authored rule ids and
 * agent-supplied event ids, so every such id embedded in a `Guardian T_*` line goes through
 * here, on the agent AND the server.
 *
 * Pure decision code (no I/O, no store or wire types, no trust-boundary authority), so it
 * belongs in this shared root (#2549). It is shared, not duplicated, because the T_wire
 * (agent) and T_server (server) lines are joined on the id: a mapping or cap that differed
 * between the two sides would silently break the join for exactly the ids that need it.
 *
 * The mapping is control bytes, DEL, space, '=' and ',' -> '_'. Bytes >= 0x80 pass through
 * unchanged. It is lossy by design: "a b" and "a_b" neutralise to the same token, and so do
 * two ids that share their first `max_bytes` bytes.
 */

#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu {

/// No length cap (the default for log_token).
inline constexpr std::size_t kLogTokenNoCap = static_cast<std::size_t>(-1);

/// The cap every `Guardian T_*` line applies to an embedded event/agent/rule id, on both
/// sides of the join. Keep it a single constant: a per-side cap breaks the join.
inline constexpr std::size_t kGuardianLogIdMaxBytes = 256;

[[nodiscard]] inline std::string log_token(std::string_view s,
                                           std::size_t max_bytes = kLogTokenNoCap) {
    if (s.size() > max_bytes)
        s = s.substr(0, max_bytes);
    std::string out;
    out.reserve(s.size());
    for (const unsigned char c : s) {
        if (c < 0x20 || c == 0x7F || c == ' ' || c == '=' || c == ',')
            out.push_back('_');
        else
            out.push_back(static_cast<char>(c));
    }
    return out;
}

} // namespace yuzu
