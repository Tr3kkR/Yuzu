/**
 * browser_policy_macos.hpp — CoreFoundation decode of one Managed
 * Preferences plist into policy rows (Apple-only).
 *
 * PRIVATE PER-PLUGIN COPY of the established CFPropertyList template (run
 * decision: no cross-plugin shared helper; consolidation is a deferred
 * follow-up). Copied from, and behaviourally identical to, in this order:
 *   - installed_apps_macos_receipts.hpp:47-58 `detail::parse_plist_root`
 *     (itself a copy of autoruns_macos.cpp's parse_plist_root): CFDataCreate
 *     -> CFPropertyListCreateWithData (kCFPropertyListImmutable), every
 *     Create-Rule reference owned by yuzu::agent::ScopedCFRef;
 *   - autoruns_macos.hpp `plist_to_launchd_fields` /
 *     `detail::cfstring_to_utf8`: the root MUST pass a
 *     CFGetTypeID == CFDictionaryGetTypeID() check before any dictionary
 *     call, and every value is type-checked before a typed read.
 * NOT os_info_macos.hpp: that is a hand-rolled substring scanner over
 * trusted Apple XML, the wrong tool for adversarial managed-preferences
 * content. Nothing here scans plist text by hand.
 *
 * Managed Preferences carries MANDATORY policy only — Chromium's macOS
 * policy loader treats a key delivered through the managed-preferences
 * domain as mandatory and only a non-managed source as recommended — so
 * every row this leg emits is Level::mandatory.
 *
 * TYPE MAPPING. Bool/Int/Real/String scalars, Array -> list, Dictionary ->
 * dict (compact JSON text via nlohmann, keys sorted). CFDate, CFData and any
 * other CF type map to the literal PolicyType::Unmodelled (value "-", detail
 * `date` / `data` / `cf_type`); a date/data NESTED inside an array or
 * dictionary renders as the JSON string "unmodelled:date" / "unmodelled:data"
 * and marks the row detail `nested_unmodelled`. A 64-bit-overflowing or
 * non-finite CFNumber and a CFString that will not convert to UTF-8 are
 * likewise unmodelled, never a silently wrong value.
 *
 * Failure tokens (string literals): `macos:plist_unparseable` (bytes are not
 * a plist), `macos:plist_not_dictionary` (root is not a dictionary),
 * `macos:plist_key_not_string`. A parse failure is CONSTRAINED at the caller,
 * never "no policy".
 */
#pragma once

#if defined(__APPLE__)

#include "browser_policy_parsers.hpp"

#include <yuzu/agent/scoped_cfref.hpp>

#include <CoreFoundation/CoreFoundation.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::browser_policy::mac {

inline constexpr std::string_view kTokenPlistUnparseable = "macos:plist_unparseable";
inline constexpr std::string_view kTokenPlistNotDictionary = "macos:plist_not_dictionary";
inline constexpr std::string_view kTokenPlistKeyNotString = "macos:plist_key_not_string";

namespace detail {

// Adopts a +1 CFPropertyListRef from CFPropertyListCreateWithData over an
// in-memory buffer — copy of installed_apps_macos_receipts.hpp:47-58.
inline bool parse_plist_root(std::string_view bytes,
                             yuzu::agent::ScopedCFRef<CFPropertyListRef>& out) {
    yuzu::agent::ScopedCFRef<CFDataRef> data(CFDataCreate(
        kCFAllocatorDefault, reinterpret_cast<const UInt8*>(bytes.data()),
        static_cast<CFIndex>(bytes.size())));
    if (!data)
        return false;
    CFErrorRef raw_error = nullptr;
    out = yuzu::agent::ScopedCFRef<CFPropertyListRef>(CFPropertyListCreateWithData(
        kCFAllocatorDefault, data.get(), kCFPropertyListImmutable, nullptr, &raw_error));
    yuzu::agent::ScopedCFRef<CFErrorRef> error(raw_error);
    return static_cast<bool>(out);
}

// Adapted from autoruns_macos.hpp detail::cfstring_to_utf8, but a failed
// conversion is nullopt (-> unmodelled), not a silent empty string, and the
// conversion is LENGTH-AWARE (CFStringGetBytes): a `std::string{buf.data()}`
// over CFStringGetCString would silently truncate at an embedded NUL (in a
// value or a dictionary key). NULs are kept here and handled at the wire
// boundary (format_policy_row replaces them and flags `nul_replaced`).
inline std::optional<std::string> cfstring_to_utf8(CFStringRef s) {
    if (s == nullptr)
        return std::nullopt;
    const CFIndex len = CFStringGetLength(s);
    if (len == 0)
        return std::string{};
    const CFIndex max_bytes = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8);
    if (max_bytes < 0)
        return std::nullopt;
    std::string out(static_cast<std::size_t>(max_bytes), '\0');
    CFIndex used = 0;
    const CFIndex converted =
        CFStringGetBytes(s, CFRangeMake(0, len), kCFStringEncodingUTF8, /*lossByte=*/0,
                         /*isExternalRepresentation=*/false,
                         reinterpret_cast<UInt8*>(out.data()), max_bytes, &used);
    if (converted != len)
        return std::nullopt; // not every UTF-16 unit converted (e.g. a lone surrogate)
    out.resize(static_cast<std::size_t>(used));
    return out;
}

/// Recursive CF -> JSON for list/dict values. Anything not representable
/// becomes an "unmodelled:<what>" string and sets `degraded`.
inline nlohmann::json cf_to_json(CFTypeRef ref, int depth, bool& degraded) {
    auto unmodelled = [&degraded](const char* what) {
        degraded = true;
        return nlohmann::json(std::string{"unmodelled:"} + what);
    };
    if (ref == nullptr)
        return nlohmann::json(nullptr);
    if (depth >= kMaxNestingDepth)
        return unmodelled("too_deep");
    const CFTypeID id = CFGetTypeID(ref);
    if (id == CFBooleanGetTypeID())
        return nlohmann::json(CFBooleanGetValue(static_cast<CFBooleanRef>(ref)) != 0);
    if (id == CFNumberGetTypeID()) {
        const auto n = static_cast<CFNumberRef>(ref);
        if (CFNumberIsFloatType(n)) {
            double d = 0;
            if (!CFNumberGetValue(n, kCFNumberDoubleType, &d) || !std::isfinite(d))
                return unmodelled("number");
            return nlohmann::json(d);
        }
        std::int64_t i = 0;
        if (!CFNumberGetValue(n, kCFNumberSInt64Type, &i))
            return unmodelled("number");
        return nlohmann::json(i);
    }
    if (id == CFStringGetTypeID()) {
        auto s = cfstring_to_utf8(static_cast<CFStringRef>(ref));
        return s ? nlohmann::json(*s) : unmodelled("string");
    }
    if (id == CFArrayGetTypeID()) {
        const auto a = static_cast<CFArrayRef>(ref);
        auto arr = nlohmann::json::array();
        for (CFIndex i = 0, n = CFArrayGetCount(a); i < n; ++i)
            arr.push_back(cf_to_json(CFArrayGetValueAtIndex(a, i), depth + 1, degraded));
        return arr;
    }
    if (id == CFDictionaryGetTypeID()) {
        const auto d = static_cast<CFDictionaryRef>(ref);
        const CFIndex n = CFDictionaryGetCount(d);
        std::vector<const void*> keys(static_cast<std::size_t>(n));
        std::vector<const void*> vals(static_cast<std::size_t>(n));
        if (n > 0)
            CFDictionaryGetKeysAndValues(d, keys.data(), vals.data());
        auto obj = nlohmann::json::object();
        for (CFIndex i = 0; i < n; ++i) {
            const auto key = static_cast<CFTypeRef>(keys[static_cast<std::size_t>(i)]);
            std::optional<std::string> k;
            if (key != nullptr && CFGetTypeID(key) == CFStringGetTypeID())
                k = cfstring_to_utf8(static_cast<CFStringRef>(key));
            if (!k) {
                degraded = true;
                continue;
            }
            obj[*k] = cf_to_json(static_cast<CFTypeRef>(vals[static_cast<std::size_t>(i)]),
                                 depth + 1, degraded);
        }
        return obj;
    }
    if (id == CFDateGetTypeID())
        return unmodelled("date");
    if (id == CFDataGetTypeID())
        return unmodelled("data");
    return unmodelled("cf_type");
}

} // namespace detail

/// Maps one top-level CF value onto the policy type enum. Total: every CF
/// type lands on a PolicyType, with Unmodelled as the explicit catch-all.
[[nodiscard]] inline PolicyValue cf_to_policy_value(CFTypeRef ref) {
    if (ref == nullptr)
        return {PolicyType::Null, "null", {}};
    const CFTypeID id = CFGetTypeID(ref);
    if (id == CFDateGetTypeID())
        return unmodelled_value("date");
    if (id == CFDataGetTypeID())
        return unmodelled_value("data");
    bool degraded = false;
    nlohmann::json j = detail::cf_to_json(ref, 0, degraded);
    if (id == CFBooleanGetTypeID() || id == CFNumberGetTypeID() || id == CFStringGetTypeID()) {
        if (degraded) // an overflowing/non-finite number or a non-UTF-8 string
            return unmodelled_value(id == CFStringGetTypeID() ? "string" : "number");
        return json_to_policy_value(j);
    }
    if (id == CFArrayGetTypeID() || id == CFDictionaryGetTypeID()) {
        PolicyValue v = json_to_policy_value(j);
        if (degraded)
            v.detail = "nested_unmodelled";
        return v;
    }
    return unmodelled_value("cf_type");
}

struct PlistPolicyParse {
    std::vector<PolicyRow> rows;
    /// Set (to a kToken* literal) when the bytes could not be read cleanly:
    /// the caller MUST record it. `rows` is empty for an unparseable /
    /// non-dictionary plist and holds the readable keys for a per-key failure.
    std::optional<std::string_view> failure;
};

/// Decodes one Managed Preferences plist (XML or binary) into rows, one per
/// top-level key, sorted by name, all Level::mandatory.
[[nodiscard]] inline PlistPolicyParse rows_from_plist_bytes(std::string_view bytes,
                                                            Browser browser,
                                                            std::string_view scope,
                                                            std::string_view source) {
    PlistPolicyParse out;
    yuzu::agent::ScopedCFRef<CFPropertyListRef> root;
    if (!detail::parse_plist_root(bytes, root)) {
        out.failure = kTokenPlistUnparseable;
        return out;
    }
    if (CFGetTypeID(root.get()) != CFDictionaryGetTypeID()) {
        out.failure = kTokenPlistNotDictionary;
        return out;
    }
    const auto dict = static_cast<CFDictionaryRef>(root.get());
    const CFIndex n = CFDictionaryGetCount(dict);
    std::vector<const void*> keys(static_cast<std::size_t>(n));
    std::vector<const void*> vals(static_cast<std::size_t>(n));
    if (n > 0)
        CFDictionaryGetKeysAndValues(dict, keys.data(), vals.data());
    for (CFIndex i = 0; i < n; ++i) {
        const auto key = static_cast<CFTypeRef>(keys[static_cast<std::size_t>(i)]);
        std::optional<std::string> name;
        if (key != nullptr && CFGetTypeID(key) == CFStringGetTypeID())
            name = detail::cfstring_to_utf8(static_cast<CFStringRef>(key));
        if (!name) {
            out.failure = kTokenPlistKeyNotString;
            continue;
        }
        PolicyRow row;
        row.browser = browser;
        row.level = Level::mandatory;
        row.scope = std::string{scope};
        row.name = std::move(*name);
        row.value = cf_to_policy_value(static_cast<CFTypeRef>(vals[static_cast<std::size_t>(i)]));
        row.source = std::string{source};
        out.rows.push_back(std::move(row));
    }
    std::sort(out.rows.begin(), out.rows.end(),
              [](const PolicyRow& a, const PolicyRow& b) { return a.name < b.name; });
    return out;
}

} // namespace yuzu::browser_policy::mac

#endif // defined(__APPLE__)
