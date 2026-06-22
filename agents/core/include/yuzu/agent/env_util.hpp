#pragma once

#include <cctype>
#include <string>

namespace yuzu::agent {

/// Value-aware truthiness for boolean environment variables.
///
/// CLI11's flag/envname binding is presence-only (any value — including "0",
/// "false", "" — reads as true), which is a footgun for a security flag like
/// `YUZU_TLS_SYSTEM_ROOTS` where `=0` must mean "stay fail-closed" (#1303 M-1).
/// This accepts the usual affirmatives (`1`/`true`/`yes`/`on`, case-insensitive,
/// surrounding whitespace trimmed); everything else — including a null pointer
/// (unset), empty, "0", "false" — is false. Header-only so both `main.cpp` and
/// the unit test (#1332 review MEDIUM — the truth table now has coverage) share
/// the one definition.
[[nodiscard]] inline bool env_truthy(const char* v) {
    if (!v)
        return false;
    std::string s{v};
    const auto ws = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && ws(static_cast<unsigned char>(s.front())))
        s.erase(s.begin());
    while (!s.empty() && ws(static_cast<unsigned char>(s.back())))
        s.pop_back();
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s == "1" || s == "true" || s == "yes" || s == "on";
}

} // namespace yuzu::agent
