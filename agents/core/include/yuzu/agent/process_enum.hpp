#pragma once

/**
 * process_enum.hpp -- Cross-platform process enumeration for Yuzu agent
 *
 * Returns a vector of ProcessInfo with PID, PPID, name, command line, and user
 * for every running process. Used by the TAR plugin for snapshot-based diff
 * detection and available to any other component that needs process data.
 *
 * Platform implementations:
 *   Windows — CreateToolhelp32Snapshot + OpenProcess/GetTokenInformation
 *   Linux   — /proc/[pid]/{status,cmdline} + getpwuid_r
 *   macOS   — sysctl(KERN_PROC_ALL) + proc_pidpath + getpwuid_r
 *
 * Thread-safe: no shared mutable state.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::agent {

struct ProcessInfo {
    uint32_t pid{0};
    uint32_t ppid{0};
    std::string name;
    std::string cmdline;
    std::string user;
};

/**
 * Enumerate all running processes on the current host.
 * Returns an empty vector on unsupported platforms or on failure.
 */
YUZU_EXPORT std::vector<ProcessInfo> enumerate_processes();

} // namespace yuzu::agent
