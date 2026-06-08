#pragma once

// RAII subprocess-capture helper for the POSIX detection paths.
// Wraps popen/pclose so the pipe FD (and the forked child) are reclaimed on
// every path, including an exception thrown while accumulating output
// (e.g. std::bad_alloc from the string append). Output is capped to bound
// memory against a pathologically chatty tool.

#if defined(__linux__) || defined(__APPLE__)

#include <array>
#include <cstdio>
#include <memory>
#include <string>

namespace yuzu::vuln {

struct PcloseDeleter {
    void operator()(FILE* f) const noexcept {
        if (f)
            pclose(f);
    }
};
using UniquePipe = std::unique_ptr<FILE, PcloseDeleter>;

// Run `cmd` via the shell and capture its stdout (trailing newlines trimmed).
// Returns an empty string if the subprocess could not be spawned. `cmd` must be
// a trusted, literal command string — never interpolate untrusted input.
inline std::string capture_command(const char* cmd,
                                   std::size_t max_bytes = 4u * 1024 * 1024) {
    std::string result;
    UniquePipe pipe(popen(cmd, "r"));
    if (!pipe)
        return result;
    std::array<char, 256> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe.get())) {
        result += buf.data();
        if (result.size() > max_bytes)
            break; // bound memory against unbounded tool output
    }
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

} // namespace yuzu::vuln

#endif // __linux__ || __APPLE__
