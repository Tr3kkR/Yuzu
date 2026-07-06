// win_sc_handle.hpp -- RAII owner for SC_HANDLE (OpenSCManager / OpenService / CreateService).
//
// Canonical home for the ScHandle pattern (#1822). Closes via CloseServiceHandle --
// NOT CloseHandle, so agents/core/src/guard_win_handle.hpp's ScopedWinHandle is the
// wrong owner for this handle type. The existing local copy in
// agents/core/src/guard_service.cpp:127-147 (and the rdp_control plugin's own copy)
// are left as-is for this change -- migrating them to this shared header is a
// separate de-dup follow-up (#1844), matching the win_str.hpp (#1681/#1682)
// precedent of landing the shared header first and sweeping call sites
// afterward. Note for that sweep: this copy adds move-ctor/move-assign;
// guard_service.cpp's copy-deleted-only original has neither, so the migration
// is not a pure textual replacement.
//
// Windows-only by construction (#ifdef _WIN32); the header is empty elsewhere.

#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace yuzu::win {

class ScHandle {
public:
    ScHandle() = default;
    ~ScHandle() { reset(); }
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
    ScHandle(ScHandle&& other) noexcept : h_(other.h_) { other.h_ = nullptr; }
    ScHandle& operator=(ScHandle&& other) noexcept {
        if (this != &other) {
            reset(other.h_);
            other.h_ = nullptr;
        }
        return *this;
    }
    void reset(SC_HANDLE h = nullptr) noexcept {
        if (h_ && h_ != h)
            CloseServiceHandle(h_);
        h_ = h;
    }
    [[nodiscard]] SC_HANDLE get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }

private:
    SC_HANDLE h_ = nullptr;
};

} // namespace yuzu::win

#endif // _WIN32
