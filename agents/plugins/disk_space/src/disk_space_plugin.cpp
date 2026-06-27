/**
 * disk_space_plugin.cpp — free disk-space query plugin for Yuzu
 *
 * Actions:
 *   "free" — Reports total / free bytes and percent-used for a single volume.
 *            Param `path` selects the volume (default platform root). A pure
 *            fact-read: thresholds live with the caller (pre-flight manifest),
 *            never in the plugin.
 *
 * Output is pipe-delimited, one row via write_output():
 *   disk|<path>|<total_bytes>|<free_bytes>|<percent_used>
 * On failure:
 *   error|<message>   (and a non-zero return)
 *
 * "free_bytes" is the space usable by an ordinary (unprivileged) caller —
 * GetDiskFreeSpaceExW's FreeBytesAvailableToCaller on Windows, statvfs
 * f_bavail*f_frsize on POSIX — which is the correct figure for an installer
 * headroom check (quota-aware), not the raw f_bfree.
 */

#include <yuzu/plugin.hpp>

#include <format>
#include <string>
#include <string_view>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/statvfs.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

#ifdef _WIN32
// Convert a UTF-8 path to UTF-16 for the wide Win32 API. The narrow Reg*A /
// *A variants apply the system code page and silently corrupt non-ASCII paths
// (#1662) — the established idiom is the wide API + an explicit CP_UTF8 decode.
std::wstring utf8_to_wide(std::string_view s) {
    if (s.empty())
        return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0)
        return {};
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}
#endif

int do_free(yuzu::CommandContext& ctx, yuzu::Params params) {
    constexpr std::string_view default_path =
#ifdef _WIN32
        "C:\\";
#else
        "/";
#endif
    const auto path = params.get("path", default_path);

    unsigned long long total_bytes = 0;
    unsigned long long free_bytes = 0;

#ifdef _WIN32
    const std::wstring wpath = utf8_to_wide(path);
    ULARGE_INTEGER avail_to_caller{}, total{}, total_free{};
    if (wpath.empty() ||
        !GetDiskFreeSpaceExW(wpath.c_str(), &avail_to_caller, &total, &total_free)) {
        ctx.write_output(std::format("error|failed to query disk space for path: {}", path));
        return 1;
    }
    total_bytes = total.QuadPart;
    free_bytes = avail_to_caller.QuadPart;

#elif defined(__linux__) || defined(__APPLE__)
    struct statvfs vfs{};
    if (statvfs(std::string(path).c_str(), &vfs) != 0) {
        ctx.write_output(std::format("error|failed to stat path: {}", path));
        return 1;
    }
    total_bytes = static_cast<unsigned long long>(vfs.f_blocks) * vfs.f_frsize;
    free_bytes = static_cast<unsigned long long>(vfs.f_bavail) * vfs.f_frsize;

#else
    ctx.write_output("error|unsupported platform");
    return 1;
#endif

    const unsigned long long used_bytes = total_bytes >= free_bytes ? total_bytes - free_bytes : 0;
    const int percent_used =
        total_bytes > 0 ? static_cast<int>((used_bytes * 100ULL) / total_bytes) : 0;

    ctx.write_output(std::format("disk|{}|{}|{}|{}", path, total_bytes, free_bytes, percent_used));
    return 0;
}

} // namespace

class DiskSpacePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "disk_space"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports free / total disk space for a single volume";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"free", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "free")
            return do_free(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(DiskSpacePlugin)
