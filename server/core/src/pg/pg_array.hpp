#pragma once

/// @file pg_array.hpp
/// Build a PostgreSQL text-array literal — `{"a","b",…}` — from a sequence of
/// strings, for binding to a `$N::text[]` parameter through
/// `pg::exec_params`. The motivating use is collapsing an N-row INSERT into one
/// statement via `unnest($1::text[], …)`: parallel arrays carry the column
/// values, so the row count is unbounded by libpq's 65535-parameter ceiling
/// (only the fixed array params count). See `SoftwareInventoryStore` for the
/// first caller (ADR-0016, issue #1664).
///
/// Escaping contract: every element is UNCONDITIONALLY double-quoted and its
/// `\` and `"` bytes backslash-escaped. Unconditional quoting is valid for ANY
/// text element and sidesteps every unquoted-element special case at once —
/// whitespace, braces, commas, and the case-insensitive bareword `NULL` (which
/// unquoted would bind a SQL NULL; quoted `"NULL"` is the four-character
/// string, never SQL NULL). This builder therefore never emits a SQL NULL
/// element; SQL NULL is not representable here by design (the callers store
/// `NOT NULL DEFAULT ''` columns).
///
/// NUL (0x00) is DROPPED. libpq's text-format parameters are NUL-terminated C
/// strings (`exec_params` passes `c_str()`), so a 0x00 anywhere in the built
/// literal would truncate the wire value mid-literal and PG would reject it as
/// a malformed array (SQLSTATE 22P02), failing the whole batch. The per-value
/// INSERT path this helper replaces silently truncated a single field at the
/// 0x00 with no error; dropping the byte here keeps the batch literal
/// well-formed and the ingest non-erroring, so a single 0x00 in one element can
/// never turn into a permanent whole-agent resend loop. Callers compute their
/// content hash from the source entries independently of this projection, so
/// dropping a byte here does not desynchronise the hash-skip compare. The
/// upstream fix (the field sanitiser should reject 0x00 outright, since PG UTF8
/// forbids it) is tracked separately and is not this helper's concern.
///
/// The caller remains responsible for byte validity in the target column
/// encoding (e.g. UTF-8 well-formedness for a UTF8 database) — this builder
/// only guarantees a syntactically well-formed array literal.

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {

[[nodiscard]] inline std::string to_text_array(const std::vector<std::string_view>& elems) {
    // Two-pass exact reserve: sum the element bytes plus 3 framing bytes each
    // (two quotes + a separating comma) plus the enclosing braces, so the common
    // (no-escape) case never reallocates — important on the up-to-20k-element
    // batch-ingest hot path. The rare `\`/`"` escape doubles a byte and falls
    // back to the string's geometric growth.
    std::size_t budget = 2;
    for (const auto& e : elems)
        budget += e.size() + 3;
    std::string out;
    out.reserve(budget);
    out.push_back('{');
    for (std::size_t i = 0; i < elems.size(); ++i) {
        if (i != 0)
            out.push_back(',');
        out.push_back('"');
        for (char c : elems[i]) {
            if (c == '\0')
                continue; // untransmittable in libpq text format — see header
            if (c == '\\' || c == '"')
                out.push_back('\\');
            out.push_back(c);
        }
        out.push_back('"');
    }
    out.push_back('}');
    return out;
}

} // namespace yuzu::server::pg
