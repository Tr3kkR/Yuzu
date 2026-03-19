/**
 * sdk_utilities.cpp — C ABI wrappers for SDK utility functions
 *
 * These wrap the C++23 header-only implementations in yuzu/sdk_utilities.hpp
 * and export them via the stable C ABI declared in yuzu/plugin.h.
 */

#include <yuzu/plugin.h>
#include <yuzu/sdk_utilities.hpp>

#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace {

/** Duplicate a std::string into a malloc'd C string. */
char* to_c_string(const std::string& s) {
    char* buf = static_cast<char*>(std::malloc(s.size() + 1));
    if (buf) {
        std::memcpy(buf, s.data(), s.size());
        buf[s.size()] = '\0';
    }
    return buf;
}

/** Build a vector of string_view from a C array of strings. */
std::vector<std::string_view> to_sv_vec(const char* const* names, size_t count) {
    std::vector<std::string_view> v;
    v.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        v.emplace_back(names[i] ? names[i] : "");
    }
    return v;
}

} // namespace

extern "C" {

YUZU_EXPORT void yuzu_free_string(char* str) {
    std::free(str);
}

YUZU_EXPORT char* yuzu_table_to_json(const char* input, const char* const* column_names,
                                     size_t column_count) {
    if (!input || !column_names || column_count == 0)
        return nullptr;

    auto cols = to_sv_vec(column_names, column_count);
    auto result = yuzu::sdk::table_to_json(input, cols);
    if (!result)
        return nullptr;
    return to_c_string(*result);
}

YUZU_EXPORT char* yuzu_json_to_table(const char* json_input, const char* const* column_names,
                                     size_t column_count) {
    if (!json_input || !column_names || column_count == 0)
        return nullptr;

    auto cols = to_sv_vec(column_names, column_count);
    auto result = yuzu::sdk::json_to_table(json_input, cols);
    if (!result)
        return nullptr;
    return to_c_string(*result);
}

YUZU_EXPORT char* yuzu_split_lines(const char* input) {
    if (!input)
        return nullptr;

    auto lines = yuzu::sdk::split_lines(input);
    std::string normalized;
    for (size_t i = 0; i < lines.size(); ++i) {
        if (i > 0)
            normalized += '\n';
        normalized += lines[i];
    }
    return to_c_string(normalized);
}

YUZU_EXPORT char* yuzu_generate_sequence(int start, int count, const char* prefix) {
    if (count <= 0)
        return nullptr;
    return to_c_string(yuzu::sdk::generate_sequence(start, count, prefix ? prefix : ""));
}

} // extern "C"
