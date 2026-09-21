/**
 * platform_security_linux.cpp -- Linux leg: the efivarfs Secure Boot reads and
 * the securityfs LSM / lockdown reads (rung 1, no spawn).
 *
 * Every file read goes through ONE errno-capturing reader (read_file); the
 * pure loops in platform_security_parsers.hpp classify the errno (ENOENT ->
 * `absent`, no token; EACCES/EPERM -> `unreadable` + `:eacces`; other errno ->
 * `unreadable` + `:errno_<n>`). Paths are the constexpr tables in the parsers
 * header: the actions take no parameters, so no request text reaches a path.
 * efivarfs must be read from offset 0 into a buffer holding the whole
 * variable, so the reader loops read() into one bounded buffer; a file that
 * fills it is EFBIG (unreadable, never truncated into a value).
 */
#include "platform_security_legs.hpp"

#if defined(__linux__)

#include <yuzu/agent/scoped_fd.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <string>
#include <string_view>

namespace yuzu::platform_security {

namespace {

constexpr std::size_t kMaxFileBytes = 4096;

ReadOutcome read_file(std::string_view path) {
    const std::string p{path};
    int raw;
    do {
        raw = ::open(p.c_str(), O_RDONLY | O_CLOEXEC);
    } while (raw < 0 && errno == EINTR);
    if (raw < 0) return {errno, {}};
    yuzu::agent::ScopedFd fd(raw);

    std::string data;
    char buf[kMaxFileBytes];
    for (ssize_t n = 1; n != 0;) {
        do {
            n = ::read(fd.get(), buf, sizeof buf);
        } while (n < 0 && errno == EINTR);
        if (n < 0) return {errno, {}}; // evaluated before the owner closes the fd on return
        data.append(buf, static_cast<std::size_t>(n));
        if (data.size() >= kMaxFileBytes) return {EFBIG, {}};
    }
    return {0, std::move(data)};
}

} // namespace

int collect_secure_boot_linux(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    emit_rows(ctx, secure_boot_rows_linux(read_file, acc), acc);
    return 0;
}

int collect_code_integrity_linux(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    emit_rows(ctx, code_integrity_rows_linux(read_file, acc), acc);
    return 0;
}

} // namespace yuzu::platform_security

#endif // defined(__linux__)
