#pragma once

/// @file web_utils.hpp
/// Pure utility functions for the Yuzu web server layer.
/// Extracted here for testability.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <format>
#include <string>
#include <string_view>

namespace yuzu::server {

/// Decode a Base64-encoded string.
inline std::string base64_decode(const std::string& in) {
    static constexpr unsigned char kTable[256] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62,
        64, 64, 64, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0,
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64};
    std::string out;
    out.reserve(in.size() * 3 / 4);
    unsigned int val = 0;
    int bits = -8;
    for (unsigned char c : in) {
        if (kTable[c] == 64)
            continue;
        val = (val << 6) | kTable[c];
        bits += 6;
        if (bits >= 0) {
            out += static_cast<char>((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return out;
}

/// Escape JSON metacharacters in a string so the result is safe to embed
/// inside a JSON string literal. Used in particular for HTMX `hx-vals`
/// attributes — the browser un-HTML-escapes the attribute value *before*
/// HTMX's JSON parser sees it, so a `"` in any value (after `html_escape`
/// becomes `&quot;`, which the browser un-escapes to `"`) would otherwise
/// close the JSON string and inject keys into the form. The correct
/// pattern is JSON-escape FIRST, then HTML-escape the result, so the
/// surrounding html_escape on the JSON-attribute literal is safe.
///
/// Caller is responsible for the final html_escape pass; this function
/// only addresses JSON metacharacters and C0 control bytes per RFC 8259.
/// Multi-byte UTF-8 sequences pass through unchanged — JSON does not
/// require U+2028/U+2029 escaping unless the parser is JS `eval`, which
/// is not the case here.
inline std::string json_escape(std::string_view in) {
    std::string out;
    out.reserve(in.size() + 4);
    for (char c : in) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x",
                              static_cast<unsigned char>(c));
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

/// Escape HTML special characters for safe rendering.
inline std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        case '\'':
            out += "&#39;";
            break;
        default:
            out += c;
        }
    }
    return out;
}

/// Percent-decode a URL-encoded string (also handles + as space).
inline std::string url_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hex = s.substr(i + 1, 2);
            out += static_cast<char>(std::stoul(hex, nullptr, 16));
            i += 2;
        } else if (s[i] == '+') {
            out += ' ';
        } else {
            out += s[i];
        }
    }
    return out;
}

/// Extract a value from a URL-encoded form body by key name.
inline std::string extract_form_value(const std::string& body, const std::string& key) {
    auto needle = key + "=";
    auto pos = body.find(needle);
    if (pos == std::string::npos)
        return {};
    pos += needle.size();
    auto end = body.find('&', pos);
    auto raw = body.substr(pos, end == std::string::npos ? end : end - pos);
    return url_decode(raw);
}

/// Extract plugin name from a command_id string (format: "plugin-timestamp").
inline std::string extract_plugin(const std::string& command_id) {
    auto dash = command_id.find('-');
    if (dash != std::string::npos) {
        return command_id.substr(0, dash);
    }
    return command_id;
}

// ============================================================================
// Time formatting and now-epoch — used by the executions surface and the TAR
// dashboard. Both surfaces standardise on UTC; relative time goes in the cell
// text, ISO-8601 UTC goes in the title= attribute for forensic copy/paste.
// Mixing local time anywhere is a known failure mode (BST/UTC drift).
// ============================================================================

/// Current epoch seconds (UTC). Equivalent to `std::time(nullptr)` but uses
/// `std::chrono` so it compiles cleanly on every platform.
inline int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// Format epoch seconds as RFC 3339 / ISO 8601 in UTC: "YYYY-MM-DDTHH:MM:SSZ".
/// Used in `title=` attributes so operators can copy a precise timestamp.
/// Returns "—" for non-positive input (sentinel "never").
inline std::string format_iso_utc(int64_t epoch_secs) {
    if (epoch_secs <= 0) return "—";
    std::time_t t = static_cast<std::time_t>(epoch_secs);
    std::tm tm_val{};
#ifdef _WIN32
    gmtime_s(&tm_val, &t);
#else
    gmtime_r(&t, &tm_val);
#endif
    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                        tm_val.tm_year + 1900, tm_val.tm_mon + 1, tm_val.tm_mday,
                        tm_val.tm_hour, tm_val.tm_min, tm_val.tm_sec);
}

/// Format a delta as a coarse "Xs/Xm/Xh/Xd ago" string. Caller passes both
/// epochs so the function is pure and easy to test (no clock read). Argument
/// order is (then, now) to match the existing `format_age` helper in
/// dashboard_routes.cpp — eases a future dedup. `epoch_then <= 0` returns
/// "—" (never-fired sentinel).
inline std::string format_relative_time(int64_t epoch_then, int64_t epoch_now) {
    if (epoch_then <= 0) return "—";
    int64_t delta = epoch_now - epoch_then;
    if (delta < 0) delta = 0;
    if (delta < 60)    return std::format("{}s ago", delta);
    if (delta < 3600)  return std::format("{}m ago", delta / 60);
    if (delta < 86400) return std::format("{}h {}m ago", delta / 3600, (delta % 3600) / 60);
    int64_t days = delta / 86400;
    int64_t hours = (delta % 86400) / 3600;
    if (days < 30) return std::format("{}d {}h ago", days, hours);
    return std::format("{}d ago", days);
}

// ============================================================================
// UTF-8 truncation — first-error preview in the executions list shows up to
// 80 chars. Truncating mid-codepoint produces invalid UTF-8 that breaks the
// browser's title= rendering; this walks back to the previous codepoint
// boundary if needed.
// ============================================================================

/// Truncate `s` to at most `max_chars` *bytes*, walking back to the previous
/// UTF-8 codepoint boundary if the cut would tear a multi-byte sequence.
/// Appends `"…"` (3 bytes UTF-8) when truncation occurred. Returns the input
/// unchanged if `s.size() <= max_chars`.
inline std::string truncate_utf8(std::string_view s, std::size_t max_chars) {
    if (s.size() <= max_chars) return std::string(s);
    std::size_t cut = max_chars;
    while (cut > 0) {
        unsigned char c = static_cast<unsigned char>(s[cut]);
        // 10xxxxxx is a continuation byte — walk back until we land on a
        // codepoint start (0xxxxxxx or 11xxxxxx).
        if ((c & 0xC0) != 0x80) break;
        --cut;
    }
    std::string out(s.substr(0, cut));
    out += "\xE2\x80\xA6"; // U+2026 HORIZONTAL ELLIPSIS, UTF-8
    return out;
}

// ============================================================================
// Status sparkbar — 4-segment stacked bar showing fan-out by agent status.
// Encoding: count → length, status → hue. Renders as inline SVG so the list
// view can ship it without a JS chart library and so screen readers can
// announce a single role="img" with a summary aria-label.
//
// Width is fixed at 120px so all rows align. Heights at 10px so the bar is
// dense but still legible. Buckets with count 0 emit no <rect> (avoids a
// 0-width artifact in some browsers). When `total == 0` (no agents matched
// scope) the bar renders a single hatched/empty cell so the row doesn't look
// like a successful zero-agent run.
//
// Color tokens: Cisco Momentum success/error/stable/text-tertiary. Theme-
// agnostic — light and dark mode both read the same SVG via CSS vars.
// ============================================================================

/// Inline SVG, ~120×10px, rendering a 4-segment stacked status sparkbar.
/// Caller is responsible for any wrapping HTML.
inline std::string render_status_sparkbar(int succeeded, int failed,
                                          int running, int pending) {
    constexpr int kWidth = 120;
    constexpr int kHeight = 10;
    const int total = succeeded + failed + running + pending;

    auto label = total > 0
                     ? std::format("{} succeeded, {} failed, {} running, {} pending of {}",
                                   succeeded, failed, running, pending, total)
                     : std::string{"no agents matched scope"};

    std::string out;
    out.reserve(512);
    out += std::format(
        "<svg class=\"status-sparkbar\" width=\"{}\" height=\"{}\" "
        "viewBox=\"0 0 {} {}\" role=\"img\" aria-label=\"{}\">",
        kWidth, kHeight, kWidth, kHeight, label);

    if (total <= 0) {
        // Hatched empty state — no agents matched scope.
        out += std::format(
            "<defs><pattern id=\"empty-hatch\" patternUnits=\"userSpaceOnUse\" "
            "width=\"4\" height=\"4\" patternTransform=\"rotate(45)\">"
            "<line x1=\"0\" y1=\"0\" x2=\"0\" y2=\"4\" "
            "stroke=\"var(--mds-color-theme-text-tertiary)\" "
            "stroke-width=\"1\" aria-hidden=\"true\" /></pattern></defs>"
            "<rect x=\"0\" y=\"0\" width=\"{}\" height=\"{}\" "
            "fill=\"url(#empty-hatch)\" aria-hidden=\"true\" />",
            kWidth, kHeight);
        out += "</svg>";
        return out;
    }

    // Compute segment widths in fixed-point so the four rounded values sum
    // exactly to kWidth — the last non-zero segment absorbs rounding error.
    struct Seg { int count; const char* fill; };
    Seg segs[4] = {
        {succeeded, "var(--mds-color-bg-success-emphasis)"},
        {failed,    "var(--mds-color-theme-indicator-error)"},
        {running,   "var(--mds-color-theme-indicator-stable)"},
        {pending,   "var(--mds-color-theme-text-tertiary)"},
    };
    int widths[4] = {0, 0, 0, 0};
    int last_nonzero = -1;
    int allocated = 0;
    for (int i = 0; i < 4; ++i) {
        if (segs[i].count > 0) {
            widths[i] = static_cast<int>(
                static_cast<int64_t>(segs[i].count) * kWidth / total);
            allocated += widths[i];
            last_nonzero = i;
        }
    }
    if (last_nonzero >= 0 && allocated < kWidth) {
        widths[last_nonzero] += (kWidth - allocated);
    }

    int x = 0;
    for (int i = 0; i < 4; ++i) {
        if (segs[i].count <= 0) continue;
        out += std::format(
            "<rect x=\"{}\" y=\"0\" width=\"{}\" height=\"{}\" fill=\"{}\" "
            "aria-hidden=\"true\" />",
            x, widths[i], kHeight, segs[i].fill);
        x += widths[i];
    }
    out += "</svg>";
    return out;
}

// ============================================================================
// Duration bar — single-axis horizontal bar inline in the per-agent table.
// Scaled to the slowest agent in the current execution so the eye picks out
// tail-latency outliers. Server-rendered as a div with a width percentage so
// no JS chart library is needed.
// ============================================================================

/// Render a duration bar as an inline `<div>`. `duration_ms` and
/// `max_duration_ms` are agent timing in this execution; `status_class` is
/// one of "completed" / "failed" / "running" / "pending" and selects the hue.
inline std::string render_duration_bar_html(int64_t duration_ms,
                                            int64_t max_duration_ms,
                                            std::string_view status_class) {
    if (duration_ms < 0) duration_ms = 0;
    int pct = 0;
    if (max_duration_ms > 0) {
        int64_t scaled = duration_ms * 100 / max_duration_ms;
        if (scaled > 100) scaled = 100;
        pct = static_cast<int>(scaled);
    }
    return std::format(
        "<div class=\"duration-bar duration-bar--{}\" "
        "style=\"width:{}%\" role=\"img\" aria-label=\"{} ms\"></div>",
        status_class, pct, duration_ms);
}

} // namespace yuzu::server
