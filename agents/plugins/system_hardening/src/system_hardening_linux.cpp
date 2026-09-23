/**
 * system_hardening_linux.cpp -- Linux leg: the allowlisted /proc/sys reads.
 *
 * SHAPE, NOT A COPY, of vuln_scan's config_checks.hpp:73-80 read_proc_value
 * (single path, first line). That helper returns {} for ENOENT, EACCES and
 * every other failure alike; a posture plugin must not, so this reader uses
 * ::open(O_RDONLY|O_CLOEXEC) + ::read and hands the captured errno back to
 * the pure collect loop (system_hardening_parsers.hpp), which classifies it.
 * Only a successful read yields a value. No shell, no sysctl binary, no
 * directory walk: the key -> path table is kLinuxAllowlist.
 *
 * A leaf ENOENT is only trusted as genuine absence when the nearest existing directory
 * above it (up to /proc/sys) is confirmed to be a procfs mount (statfs magic) -- otherwise it is remapped to ENODEV before it
 * reaches the pure layer (remap_enoent_for_surface), so a runtime that hides or
 * replaces /proc/sys or a subtree of it (ProcSubset=pid, a tmpfs overmount, a container or
 * chroot that does not expose it)
 * never reports a clean absent/OK for hardening it never probed. Same rule as the
 * sibling platform_security plugin's efivarfs/securityfs check (PR #4792 review).
 * In a default container /proc/sys IS procfs, and these eleven keys are kernel-global
 * (not namespaced), so a containerised agent reads the host kernel's real values.
 */
#include "system_hardening_legs.hpp"

#if defined(__linux__)

#include <yuzu/agent/scoped_fd.hpp>

#include <fcntl.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <cerrno>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::system_hardening {

namespace {

// A /proc/sys integer is a handful of bytes; anything longer is not a value
// this table models (it maps to `unmodelled`, not a failure).
constexpr std::size_t kMaxValueBytes = 256;

// linux/magic.h's ABI-stable PROC_SUPER_MAGIC, not included directly to avoid a
// kernel-header build dependency this TU otherwise has no need for.
constexpr decltype(std::declval<struct statfs>().f_type) kProcSuperMagic = 0x9fa0;

// True iff the nearest existing directory above `leaf` (surface_probe_dirs, stopping at
// /proc/sys) is a procfs mount. False on any statfs failure other than a missing directory,
// and false when no directory up to /proc/sys exists -- never guessed true.
bool surface_is_procfs(std::string_view leaf) {
    for (const auto& dir : surface_probe_dirs(leaf)) {
        struct statfs buf {};
        if (::statfs(dir.c_str(), &buf) == 0) return buf.f_type == kProcSuperMagic;
        if (errno != ENOENT) return false;
    }
    return false;
}

ReadOutcome read_proc_sys(std::string_view path) {
    const std::string p{path};
    int raw;
    do {
        raw = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);
    } while (raw < 0 && errno == EINTR);
    if (raw < 0) {
        const int open_errno = errno; // captured before the statfs probe can touch errno
        const bool mounted = open_errno == ENOENT ? surface_is_procfs(path) : true;
        return {remap_enoent_for_surface(open_errno, mounted), 0, {}};
    }
    yuzu::agent::ScopedFd fd(raw);

    char buf[kMaxValueBytes];
    ssize_t n;
    do {
        n = ::read(fd.get(), buf, sizeof buf);
    } while (n < 0 && errno == EINTR);
    const int read_errno = (n < 0) ? errno : 0; // captured before the owner closes the fd on return
    if (n < 0) return {read_errno, 0, {}};
    return {0, 0, std::string(buf, static_cast<std::size_t>(n))};
}

} // namespace

int collect_posture_linux(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = collect_linux_posture(read_proc_sys, acc);
    emit_posture(ctx, rows, acc);
    return 0;
}

} // namespace yuzu::system_hardening

#endif // defined(__linux__)
