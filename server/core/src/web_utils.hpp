#pragma once

/// @file web_utils.hpp
/// Pure utility functions for the Yuzu web server layer.
/// Extracted here for testability.

#include <cstddef>
#include <cstdio>
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

} // namespace yuzu::server
