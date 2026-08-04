// win_reg_handle.hpp -- RAII owners for HKEY and RegLoadKeyW-mounted hives.
//
// Canonical home for the HKEY-RAII pattern (PR1.7). Six independent copies of
// this shape exist across the tree (licensing_win.cpp's HKeyCloser/
// HiveUnloadGuard, installed_apps_plugin.cpp's function-local closer,
// tar_mapdrive_collector.cpp's RegKeyGuard/HiveUnloadGuard, plus .put()-style
// wrappers in rdp_control_plugin.cpp and tar_software_collector.cpp) --
// mirrors the win_sc_handle.hpp (#1822) precedent of landing a shared header
// first; sweeping the existing call sites onto it is a separate follow-up,
// matching that precedent's own note about win_str.hpp/#1681.
//
// Windows-only by construction (#ifdef _WIN32); the header is empty
// elsewhere.

#pragma once

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <utility>

namespace yuzu::win {

// RAII owner for a HKEY obtained from RegOpenKeyExW / RegCreateKeyExW /
// RegLoadKeyW's mount root. Closes via RegCloseKey on destruction.
// Non-copyable (copying would double-close); movable. Never wrap a
// predefined constant (HKEY_LOCAL_MACHINE, HKEY_USERS, ...) in this type --
// those are not owned handles and RegCloseKey on one is a no-op that masks
// a real bug if ever passed here by mistake.
class RegKey {
public:
    RegKey() = default;
    explicit RegKey(HKEY h) noexcept : h_(h) {}
    ~RegKey() { reset(); }

    RegKey(const RegKey&) = delete;
    RegKey& operator=(const RegKey&) = delete;

    RegKey(RegKey&& other) noexcept : h_(other.h_) { other.h_ = nullptr; }
    RegKey& operator=(RegKey&& other) noexcept {
        if (this != &other) {
            reset();
            h_ = other.h_;
            other.h_ = nullptr;
        }
        return *this;
    }

    void reset(HKEY h = nullptr) noexcept {
        if (h_ && h_ != h)
            RegCloseKey(h_);
        h_ = h;
    }

    [[nodiscard]] HKEY get() const noexcept { return h_; }

    /// Out-param target for RegOpenKeyExW / RegCreateKeyExW. Closes any
    /// handle this instance already owns first, so reusing a RegKey for a
    /// second open can never leak the handle it is about to overwrite.
    [[nodiscard]] HKEY* put() noexcept {
        reset();
        return &h_;
    }

    explicit operator bool() const noexcept { return h_ != nullptr; }

private:
    HKEY h_{nullptr};
};

// A private, process-scoped RegLoadKeyW mount of an offline hive file (e.g.
// a profile's NTUSER.DAT) under HKEY_USERS, unloaded on destruction.
//
// A leaked mount is SYSTEM-WIDE, survives process death, and locks the
// source file until it is unloaded or the host reboots -- most commonly a
// transient third-party handle (Search Indexer, AV, System Restore) into the
// mounted branch, recoverable without reboot once that holder releases; a
// genuinely stuck holder is the rarer case reboot actually resolves:
// installed_apps_plugin.cpp:165-166, licensing_win.cpp:70-104, and
// tar_mapdrive_collector.cpp each independently hit and documented exactly
// this failure mode. with_root() is the only
// sanctioned way to read the mounted hive through this type: it hands the
// caller a borrowed HKEY for the duration of one callback and closes that
// handle before returning, so a handle into the mount cannot accidentally
// outlive the mount -- there is no other way to obtain one.
class ScopedUserHive {
public:
    /// Attempts RegLoadKeyW(HKEY_USERS, mount_name, hive_file_path) immediately.
    /// `unload_failed`, if non-null, is set (never cleared) when
    /// RegUnLoadKeyW fails in the destructor -- read it AFTER this guard
    /// goes out of scope, since a destructor cannot throw or return a status
    /// (mirrors licensing_win.cpp's HiveUnloadGuard).
    ScopedUserHive(std::wstring mount_name, const std::wstring& hive_file_path,
                   bool* unload_failed = nullptr)
        : mount_name_(std::move(mount_name)), unload_failed_(unload_failed) {
        loaded_ = (RegLoadKeyW(HKEY_USERS, mount_name_.c_str(), hive_file_path.c_str()) ==
                   ERROR_SUCCESS);
    }

    ~ScopedUserHive() {
        if (loaded_ && RegUnLoadKeyW(HKEY_USERS, mount_name_.c_str()) != ERROR_SUCCESS &&
            unload_failed_)
            *unload_failed_ = true;
    }

    ScopedUserHive(const ScopedUserHive&) = delete;
    ScopedUserHive& operator=(const ScopedUserHive&) = delete;
    ScopedUserHive(ScopedUserHive&&) = delete;
    ScopedUserHive& operator=(ScopedUserHive&&) = delete;

    /// True iff RegLoadKeyW succeeded. with_root() is a no-op (returns
    /// false) when this is false.
    [[nodiscard]] bool ok() const noexcept { return loaded_; }

    /// Opens the mount's root key, calls fn(root), and closes the root --
    /// all synchronously, before returning -- so no handle into the mount
    /// survives past this call. Returns false without calling fn if the
    /// mount never loaded or the root could not be (re-)opened.
    template <typename Fn>
    bool with_root(Fn&& fn) {
        if (!loaded_)
            return false;
        RegKey root;
        if (RegOpenKeyExW(HKEY_USERS, mount_name_.c_str(), 0, KEY_READ, root.put()) !=
            ERROR_SUCCESS)
            return false;
        fn(root.get());
        return true;
    }

private:
    std::wstring mount_name_;
    bool* unload_failed_{nullptr};
    bool loaded_{false};
};

} // namespace yuzu::win

#endif // _WIN32
