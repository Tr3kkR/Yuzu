#pragma once

#include <cstring>
#include <string>

namespace yuzu {

/// Securely zero a string's contents so key material does not persist in freed memory.
inline void secure_zero(std::string& s) {
    if (s.empty()) return;
#if defined(__linux__)
    explicit_bzero(s.data(), s.size());
#else
    // Portable: volatile write prevents dead-store elimination.
    // Works on Windows, macOS, and other platforms.
    volatile char* p = s.data();
    for (size_t i = 0; i < s.size(); ++i) {
        p[i] = 0;
    }
#endif
    s.clear();
}

}  // namespace yuzu
