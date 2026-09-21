/**
 * local_security_policy_legs.hpp -- the seam between the portable plugin TU and the
 * per-OS leg TUs, plus the thin OS shells the legs share (POSIX readers, the
 * CFPropertyList bridge). Every decision lives in local_security_policy_parsers.hpp.
 * Each collect_* is defined by exactly one leg TU; a read returns 0, degradation is the status.
 */
#pragma once

#include "local_security_policy_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <spdlog/spdlog.h>

#include <string_view>

#if !defined(_WIN32)
#include <yuzu/agent/scoped_fd.hpp>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <posix_dir_walk.hpp>
#endif
#if defined(__APPLE__)
#include <yuzu/agent/scoped_cfref.hpp>

#include <CoreFoundation/CoreFoundation.h>
#endif

namespace yuzu::local_security_policy {

int collect_linux_policy(yuzu::CommandContext& ctx, std::string_view action);
int collect_macos_policy(yuzu::CommandContext& ctx, std::string_view action);
int collect_windows_policy(yuzu::CommandContext& ctx, std::string_view action,
                           std::string_view data_dir);

/// Writes the rows and the one status every leg reports (PERMISSION_DENIED only
/// when nothing existing was readable -- see select_status).
inline int apply_collected(yuzu::CommandContext& ctx, const Collected& c) {
    for (const auto& r : c.rows) ctx.write_output(r);
    switch (c.status) {
    case PolicyStatus::Ok:
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        break;
    case PolicyStatus::PermissionDenied:
        spdlog::warn("local_security_policy: permission denied ({})", c.reason);
        ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              c.reason);
        break;
    case PolicyStatus::Constrained:
        spdlog::warn("local_security_policy: degraded read ({})", c.reason);
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              c.reason);
        break;
    }
    return 0;
}

#if !defined(_WIN32)

/// Bounded regular-file read. Symlinks ARE followed: /etc/pam.d/system-auth is a symlink
/// into /etc/authselect on RHEL-family hosts (real capture, fedora:40); all paths are under /etc.
inline FileRead posix_read_file(const std::string& path) {
    yuzu::agent::ScopedFd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (!fd) return {errno, {}};
    struct stat st{};
    if (::fstat(fd.get(), &st) != 0) return {errno, {}};
    if (!S_ISREG(st.st_mode)) return {kReadNotRegular, {}};
    FileRead out;
    char buf[8192];
    for (;;) {
        const ssize_t n = ::read(fd.get(), buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            return {errno, {}};
        }
        if (n == 0) break;
        out.data.append(buf, static_cast<std::size_t>(n));
        if (out.data.size() > kMaxFileBytes) return {kReadOversized, {}};
    }
    return out;
}

inline DirList posix_list_dir(const std::string& path) {
    DirList out;
    DIR* d = ::opendir(path.c_str());
    if (d == nullptr) {
        out.err = errno;
        return out;
    }
    const auto walk = yuzu::shared::walk_dir_capped(d, kMaxDirEntries, [&](const dirent* e) {
        out.names.emplace_back(e->d_name);
        return true;
    });
    ::closedir(d);
    out.truncated = walk.truncated;
    if (walk.enumeration_error) out.err = EIO;
    std::sort(out.names.begin(), out.names.end());
    return out;
}

#endif // !_WIN32

#if defined(__APPLE__)

namespace detail {

inline std::string cf_to_utf8(CFStringRef s) {
    char buf[1024];
    return CFStringGetCString(s, buf, sizeof(buf), kCFStringEncodingUTF8) ? std::string{buf}
                                                                          : std::string{};
}

/// Scalar CF value -> text; nullopt for a nested/unknown type (never guessed).
inline std::optional<std::string> cf_scalar_text(CFTypeRef v) {
    if (v == nullptr) return std::nullopt;
    if (CFGetTypeID(v) == CFStringGetTypeID()) return cf_to_utf8(static_cast<CFStringRef>(v));
    if (CFGetTypeID(v) == CFBooleanGetTypeID())
        return std::string{CFBooleanGetValue(static_cast<CFBooleanRef>(v)) ? "true" : "false"};
    if (CFGetTypeID(v) == CFNumberGetTypeID()) {
        const auto n = static_cast<CFNumberRef>(v);
        long long i = 0;
        CFNumberGetValue(n, kCFNumberLongLongType, &i);
        return std::to_string(i);
    }
    return std::nullopt;
}

inline std::vector<std::pair<std::string, CFTypeRef>> cf_dict_entries(CFDictionaryRef d) {
    std::vector<std::pair<std::string, CFTypeRef>> out;
    const CFIndex n = CFDictionaryGetCount(d);
    std::vector<const void*> keys(static_cast<std::size_t>(n)), vals(static_cast<std::size_t>(n));
    CFDictionaryGetKeysAndValues(d, keys.data(), vals.data());
    for (CFIndex i = 0; i < n; ++i)
        if (CFGetTypeID(static_cast<CFTypeRef>(keys[i])) == CFStringGetTypeID())
            out.emplace_back(cf_to_utf8(static_cast<CFStringRef>(keys[i])), static_cast<CFTypeRef>(vals[i]));
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    return out;
}

} // namespace detail

/// pwpolicy plist half: XML -> PwPolicyItems via CFPropertyListCreateWithData (no hand-rolled
/// scan); nullopt when CF rejects the bytes or the root is not a dictionary. Inline so the
/// unit suite can call it (a symbol inside the dlopen'd plugin is not reachable).
inline std::optional<std::vector<PwPolicyItem>> pwpolicy_plist_to_items(std::string_view xml) {
    yuzu::agent::ScopedCFRef<CFDataRef> data(CFDataCreate(
        kCFAllocatorDefault, reinterpret_cast<const UInt8*>(xml.data()), static_cast<CFIndex>(xml.size())));
    if (!data) return std::nullopt;
    CFErrorRef raw_err = nullptr;
    yuzu::agent::ScopedCFRef<CFPropertyListRef> plist(CFPropertyListCreateWithData(
        kCFAllocatorDefault, data.get(), kCFPropertyListImmutable, nullptr, &raw_err));
    yuzu::agent::ScopedCFRef<CFErrorRef> err(raw_err);
    if (!plist || CFGetTypeID(plist.get()) != CFDictionaryGetTypeID()) return std::nullopt;

    std::vector<PwPolicyItem> items;
    for (const auto& [category, value] : detail::cf_dict_entries(static_cast<CFDictionaryRef>(plist.get()))) {
        if (CFGetTypeID(value) != CFArrayGetTypeID()) {
            items.push_back({category, "", "", {}}); // not the documented shape -> unmodelled_category
            continue;
        }
        const auto arr = static_cast<CFArrayRef>(value);
        for (CFIndex i = 0; i < CFArrayGetCount(arr); ++i) {
            const auto el = static_cast<CFTypeRef>(CFArrayGetValueAtIndex(arr, i));
            if (CFGetTypeID(el) != CFDictionaryGetTypeID()) continue;
            PwPolicyItem it{category, "", "", {}};
            for (const auto& [k, v] : detail::cf_dict_entries(static_cast<CFDictionaryRef>(el))) {
                if (k == "policyIdentifier") it.identifier = detail::cf_scalar_text(v).value_or("");
                else if (k == "policyContent") it.content = detail::cf_scalar_text(v).value_or("");
                else if (k == "policyParameters" && CFGetTypeID(v) == CFDictionaryGetTypeID())
                    for (const auto& [pk, pv] : detail::cf_dict_entries(static_cast<CFDictionaryRef>(v)))
                        it.params.emplace_back(pk, detail::cf_scalar_text(pv).value_or("unmodelled"));
            }
            items.push_back(std::move(it));
        }
    }
    return items;
}

#else

inline std::optional<std::vector<PwPolicyItem>> pwpolicy_plist_to_items(std::string_view) {
    return std::nullopt;
}

#endif // __APPLE__

} // namespace yuzu::local_security_policy
