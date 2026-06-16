#include "dex_linux_sysfs.hpp"

#include <charconv>

namespace yuzu::agent::lnx {

namespace {
bool is_ws(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'; }
} // namespace

std::optional<std::uint64_t> parse_throttle_count(std::string_view s) {
    std::size_t i = 0;
    while (i < s.size() && is_ws(s[i]))
        ++i;
    const std::size_t start = i;
    while (i < s.size() && !is_ws(s[i]))
        ++i;
    const std::string_view tok = s.substr(start, i - start);
    if (tok.empty())
        return std::nullopt;
    std::uint64_t v = 0;
    const char* const end = tok.data() + tok.size();
    const auto [ptr, ec] = std::from_chars(tok.data(), end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    return v;
}

} // namespace yuzu::agent::lnx
