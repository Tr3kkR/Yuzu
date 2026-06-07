#pragma once

/**
 * guard_win_handle.hpp — windows-only RAII owners for the Guardian guard watch
 * handles. Include ONLY inside `#ifdef _WIN32` (it needs <windows.h>).
 *
 * Why: the guard watch threads acquire raw HANDLEs (CreateEventW, CreateFileW for
 * ReadDirectoryChangesW, FindFirstChangeNotificationW) and do throwing work
 * (std::string / std::filesystem, and the drift sink which builds protobuf and
 * does a network write) before releasing them. A manual CloseHandle at the end of
 * run() is skipped on an exception → std::terminate (the thread callable) + a
 * handle leak. RAII releases on every exit, normal or exceptional.
 *
 * Also normalises `INVALID_HANDLE_VALUE` → `nullptr`: FindFirstChangeNotificationW
 * returns INVALID_HANDLE_VALUE (a TRUTHY -1), not null, on failure — storing it raw
 * made `if (handle)` wrongly true, feeding an invalid handle to
 * WaitForMultipleObjects (→ WAIT_FAILED → silent guard death) and calling
 * FindCloseChangeNotification(-1). The owner treats both sentinels as empty.
 */

#include <windows.h>

namespace yuzu::agent::detail {

inline void close_handle_(HANDLE h) { ::CloseHandle(h); }
inline void cancel_and_close_(HANDLE h) {
    ::CancelIo(h); // cancel any pending overlapped read issued on this (run-)thread
    ::CloseHandle(h);
}
inline void find_close_(HANDLE h) { ::FindCloseChangeNotification(h); }

/// Single-owner RAII for a Win32 HANDLE released via `CloseFn`. Non-copyable,
/// movable. Both `nullptr` and `INVALID_HANDLE_VALUE` mean "empty".
template <void (*CloseFn)(HANDLE)>
class ScopedWinHandle {
public:
    ScopedWinHandle() = default;
    explicit ScopedWinHandle(HANDLE h) : h_(norm(h)) {}
    ~ScopedWinHandle() { reset(); }

    ScopedWinHandle(const ScopedWinHandle&) = delete;
    ScopedWinHandle& operator=(const ScopedWinHandle&) = delete;
    ScopedWinHandle(ScopedWinHandle&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
    ScopedWinHandle& operator=(ScopedWinHandle&& o) noexcept {
        if (this != &o) {
            reset();
            h_ = o.h_;
            o.h_ = nullptr;
        }
        return *this;
    }

    HANDLE get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }
    void reset(HANDLE h = nullptr) {
        if (h_)
            CloseFn(h_);
        h_ = norm(h);
    }

private:
    static HANDLE norm(HANDLE h) {
        return (h == nullptr || h == INVALID_HANDLE_VALUE) ? nullptr : h;
    }
    HANDLE h_ = nullptr;
};

using EventHandle = ScopedWinHandle<&close_handle_>;          ///< CreateEventW
using DirHandle = ScopedWinHandle<&cancel_and_close_>;        ///< CreateFileW (overlapped dir watch)
using ChangeNotifyHandle = ScopedWinHandle<&find_close_>;     ///< FindFirstChangeNotificationW

} // namespace yuzu::agent::detail
