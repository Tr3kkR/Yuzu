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
 */
#include "system_hardening_legs.hpp"

#if defined(__linux__)

#include <yuzu/agent/scoped_fd.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <string>
#include <string_view>

namespace yuzu::system_hardening {

namespace {

// A /proc/sys integer is a handful of bytes; anything longer is not a value
// this table models (it maps to `unmodelled`, not a failure).
constexpr std::size_t kMaxValueBytes = 256;

ReadOutcome read_proc_sys(std::string_view path) {
    const std::string p{path};
    int raw;
    do {
        raw = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);
    } while (raw < 0 && errno == EINTR);
    yuzu::agent::ScopedFd fd(raw);
    if (!fd) return {errno, 0, {}};

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
