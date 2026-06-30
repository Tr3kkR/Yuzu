#pragma once

/// @file utf8_sanitize.hpp
/// Strict UTF-8 scrubbing for untrusted agent-supplied text columns before they
/// reach PostgreSQL. Lifted verbatim from `inventory_ingestion.cpp` so the
/// inventory ingest seam and the app_perf ingest seam share ONE implementation
/// (a TEXT field reaching PG with an invalid byte is rejected with SQLSTATE
/// 22021, rolling back the whole ingest transaction).
///
/// NOTE on the inventory hash-coordination invariant: the agent's installed_software
/// source carries a byte-identical copy (`clamp_field` →
/// `sanitize_utf8_strict` in sync_source_installed_software.cpp). The two MUST stay
/// byte-for-byte identical or the agent's and server's canonical hashes diverge →
/// permanent always-full. This header is the SERVER side of that pair; editing it
/// means editing the agent copy in lockstep. (app_perf does NOT participate in that
/// invariant — it is hash-less — so it can consume this freely.)

#include <cstddef>
#include <string>
#include <string_view>

namespace yuzu::server {

/// Replace every byte that is not part of a valid UTF-8 sequence with U+FFFD (the
/// replacement character, EF BF BD). "Valid" is exactly what PostgreSQL's UTF8
/// server-encoding accepts: no overlong forms, no surrogates (U+D800..U+DFFF),
/// nothing above U+10FFFF.
///
/// This MUST run BEFORE any length clamp (U+FFFD is 3 bytes, so scrubbing can grow
/// the field) — see the inventory `clamp_field` ordering contract.
inline std::string sanitize_utf8_strict(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    const std::size_t n = s.size();
    const auto cont = [&](std::size_t j) -> bool {
        return j < n && (static_cast<unsigned char>(s[j]) & 0xC0) == 0x80;
    };
    std::size_t i = 0;
    while (i < n) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        const unsigned char c1 = i + 1 < n ? static_cast<unsigned char>(s[i + 1]) : 0;
        std::size_t len = 0;
        bool ok = false;
        if (c < 0x80) {
            ok = true;
            len = 1;
        } else if (c >= 0xC2 && c <= 0xDF) {
            ok = cont(i + 1);
            len = 2;
        } else if (c == 0xE0) {
            ok = c1 >= 0xA0 && c1 <= 0xBF && cont(i + 2); // reject overlong 80..9F
            len = 3;
        } else if (c >= 0xE1 && c <= 0xEC) {
            ok = cont(i + 1) && cont(i + 2);
            len = 3;
        } else if (c == 0xED) {
            ok = c1 >= 0x80 && c1 <= 0x9F && cont(i + 2); // reject surrogates A0..BF
            len = 3;
        } else if (c >= 0xEE && c <= 0xEF) {
            ok = cont(i + 1) && cont(i + 2);
            len = 3;
        } else if (c == 0xF0) {
            ok = c1 >= 0x90 && c1 <= 0xBF && cont(i + 2) && cont(i + 3); // reject overlong 80..8F
            len = 4;
        } else if (c >= 0xF1 && c <= 0xF3) {
            ok = cont(i + 1) && cont(i + 2) && cont(i + 3);
            len = 4;
        } else if (c == 0xF4) {
            ok = c1 >= 0x80 && c1 <= 0x8F && cont(i + 2) && cont(i + 3); // reject > U+10FFFF
            len = 4;
        }
        if (ok) {
            out.append(s.data() + i, len);
            i += len;
        } else {
            out.append("\xEF\xBF\xBD", 3); // U+FFFD, advance one byte
            i += 1;
        }
    }
    return out;
}

} // namespace yuzu::server
