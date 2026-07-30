#pragma once

/**
 * scoped_fd.hpp -- move-only RAII owner for a POSIX file descriptor.
 *
 * close()s the owned fd on destruction unless release()d or reset() to a new
 * value first. Header-only, POSIX-only (guarded `#ifndef _WIN32` -- Windows
 * has no POSIX fd space; HANDLE lifetime is a different animal and already
 * has its own idioms, e.g. file_hash.hpp's HANDLE overload).
 *
 * Mirrors the shape of subprocess_runner.cpp's file-local `UniqueFd` (get /
 * release / reset, move-only, close-on-destruct) but lives here as a shared
 * primitive so any POSIX caller that owns a bare fd -- a kqueue/eventfd wake
 * pipe, a one-shot `open()`, a socket -- gets the same exception-safe wrapper
 * instead of hand-rolling it again. `UniqueFd` itself is left as-is (not a
 * consumer of this header): it is scoped to subprocess_runner.cpp's own
 * exception-safety story and out of bounds for this change.
 *
 * Not a `unique_ptr` alias: -1 (not nullptr/0) is the "no fd" sentinel, and
 * the deleter is a fixed `close()` call, not a template parameter -- a small
 * dedicated type reads clearer at every call site than a custom-deleter
 * `unique_ptr<int, ...>` would.
 */

#ifndef _WIN32

#include <unistd.h> // close()

namespace yuzu::agent {

/// Owns exactly one POSIX file descriptor; closes it on destruction, move, or
/// an explicit reset() -- never double-closes, never leaks past an exception.
class scoped_fd {
public:
    scoped_fd() = default;
    explicit scoped_fd(int fd) noexcept : fd_(fd) {}

    scoped_fd(const scoped_fd&) = delete;
    scoped_fd& operator=(const scoped_fd&) = delete;

    scoped_fd(scoped_fd&& other) noexcept : fd_(other.release()) {}
    scoped_fd& operator=(scoped_fd&& other) noexcept {
        if (this != &other)
            reset(other.release());
        return *this;
    }

    ~scoped_fd() { reset(); }

    /// The raw fd, or -1 if this instance owns nothing. Ownership is retained.
    [[nodiscard]] int get() const noexcept { return fd_; }

    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
    explicit operator bool() const noexcept { return valid(); }

    /// Give up ownership without closing; the caller now owns the fd.
    [[nodiscard]] int release() noexcept {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

    /// Close the currently-owned fd (if any) and take ownership of `fd`
    /// instead (default -1: own nothing).
    void reset(int fd = -1) noexcept {
        if (fd_ >= 0)
            ::close(fd_);
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

} // namespace yuzu::agent

#endif // !_WIN32
