#pragma once

/**
 * log_token.hpp - neutralise an untrusted identifier before it is embedded in a
 * space-delimited `key=value` log line (CWE-117 log forging).
 *
 * A raw identifier that contains a newline forges a whole physical log line; one that
 * contains a space or '=' forges extra `key=value` tokens on the SAME line, which a
 * first-match parser then reads. Both are reachable from operator-authored rule ids and
 * agent-supplied event ids.
 *
 * Pure decision code (no I/O, no store or wire types, no trust-boundary authority), so it
 * belongs in this shared root (#2549). It is shared, not duplicated, because the Guardian
 * T_wire (agent) and T_server (server) lines are joined on the id: a mapping or cap that
 * differed between the two sides would silently break the join for exactly the ids that need
 * it.
 *
 * Two functions, one mapping core:
 *   - log_token(s): control bytes, DEL, space, '=' and ',' -> '_'. Bytes >= 0x80 pass
 *     through. No length cap. This is the structured-audit-detail neutraliser (audit_token in
 *     server/core/src/web_utils.hpp forwards to it).
 *   - log_id_token(s): for an id written to a Guardian log line. Stricter: every byte outside
 *     printable ASCII, plus space, '=' and ',', becomes '_' (so a multi-byte character can
 *     neither be cut mid-sequence into invalid UTF-8 nor smuggle a Unicode line separator into
 *     a line), and an id longer than kGuardianLogIdMaxBytes is shortened to exactly that
 *     length as <head> '~' <last kGuardianLogIdTailBytes bytes>. Keeping the tail matters: a
 *     Guardian event id ends in `<wall_ms>-<seq>`, the part that tells two events of one rule
 *     apart, so a plain cut would collapse every event of a long rule id onto one token.
 *
 * Both are lossy by design: "a b" and "a_b" share a token, and so do two long ids that share
 * both their head and their last kGuardianLogIdTailBytes bytes.
 */

#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu {

/// Length every `Guardian T_*` id token is shortened to, on both sides of the join. A single
/// constant: a per-side length breaks the join.
inline constexpr std::size_t kGuardianLogIdMaxBytes = 256;

/// How many bytes of the END of an over-long id survive shortening (the `<wall_ms>-<seq>`
/// suffix of a Guardian event id fits with room to spare).
inline constexpr std::size_t kGuardianLogIdTailBytes = 24;

static_assert(kGuardianLogIdMaxBytes > kGuardianLogIdTailBytes + 1,
              "an over-long id must keep a non-empty head, the marker and the tail");

[[nodiscard]] inline std::string log_token(std::string_view s) {
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

[[nodiscard]] inline std::string log_id_token(std::string_view s) {
    std::string raw;
    if (s.size() > kGuardianLogIdMaxBytes) {
        raw.reserve(kGuardianLogIdMaxBytes);
        raw.append(s.substr(0, kGuardianLogIdMaxBytes - kGuardianLogIdTailBytes - 1));
        raw.push_back('~');
        raw.append(s.substr(s.size() - kGuardianLogIdTailBytes));
    } else {
        raw.assign(s);
    }
    for (char& ch : raw) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 0x21 || c > 0x7E || c == '=' || c == ',')
            ch = '_';
    }
    return raw;
}

} // namespace yuzu
