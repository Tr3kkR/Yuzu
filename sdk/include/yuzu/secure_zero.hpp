#pragma once

#include <cstring>
#include <string>

namespace yuzu {

/// Securely zero a string's contents so key material does not persist in freed memory.
inline void secure_zero(std::string& s) {
    if (s.empty()) return;
#ifdef _WIN32
    // RtlSecureZeroMemory is a volatile-based inline in winnt.h;
    // use the compiler intrinsic to avoid pulling in <windows.h>.
    volatile char* p = s.data();
    for (size_t i = 0; i < s.size(); ++i) {
        p[i] = 0;
    }
#else
    explicit_bzero(s.data(), s.size());
#endif
    s.clear();
}

}  // namespace yuzu
