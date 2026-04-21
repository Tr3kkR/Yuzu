#pragma once

#include <yuzu/plugin.h>

#include <array>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::agent {

struct LoadError {
    std::string path;
    std::string reason;
};

/// Plugin names the agent reserves for internal dispatch (Guardian engine,
/// future system/OTA intercepts). Third-party plugins loaded at scan time
/// that declare one of these names are rejected so a compromised or
/// misconfigured plugin author cannot shadow the reserved dispatch paths.
/// See docs/yuzu-guardian-design-v1.1.md §7.2 for `__guard__`.
inline constexpr std::array<std::string_view, 3> kReservedPluginNames{
    "__guard__",   // Guardian engine (design v1.1 §7.2)
    "__system__",  // reserved for future system-scope commands
    "__update__",  // reserved for OTA update commands
};

/// Stable reason prefix recorded in LoadError::reason when a plugin is
/// rejected because its declared name is in kReservedPluginNames. Callers
/// (e.g. agent metrics) can match on this prefix to count rejections by
/// category without re-parsing free-form text.
inline constexpr std::string_view kReservedNameReason = "reserved plugin name";

/// True if name matches one of kReservedPluginNames exactly (case-sensitive).
[[nodiscard]] constexpr bool is_reserved_plugin_name(std::string_view name) noexcept {
    for (auto reserved : kReservedPluginNames) {
        if (name == reserved) return true;
    }
    return false;
}

/// SHA-256 hash a file on disk. Returns lowercase hex or empty on failure.
[[nodiscard]] std::string sha256_file(const std::filesystem::path& path);

/// Load a plugin allowlist file (one "sha256  filename" per line, like sha256sum output).
/// Returns a map of filename -> expected hash. Empty map on failure or missing file.
[[nodiscard]] std::unordered_map<std::string, std::string>
load_plugin_allowlist(const std::filesystem::path& allowlist_path);

/**
 * PluginHandle owns a loaded plugin shared library and its descriptor.
 * Unloads the library (dlclose / FreeLibrary) on destruction.
 */
class YUZU_EXPORT PluginHandle {
public:
    PluginHandle() = default;
    PluginHandle(const PluginHandle&) = delete;
    PluginHandle& operator=(const PluginHandle&) = delete;
    PluginHandle(PluginHandle&&) noexcept;
    PluginHandle& operator=(PluginHandle&&) noexcept;
    ~PluginHandle();

    [[nodiscard]] const YuzuPluginDescriptor* descriptor() const noexcept { return descriptor_; }
    [[nodiscard]] std::string_view path() const noexcept { return path_; }

    static std::expected<PluginHandle, LoadError> load(const std::filesystem::path& so_path);

private:
    void* handle_{nullptr};
    const YuzuPluginDescriptor* descriptor_{nullptr};
    std::string path_;
};

/**
 * PluginLoader scans a directory for .so/.dll files, loads each one,
 * verifies the ABI version, and returns handles.
 */
class YUZU_EXPORT PluginLoader {
public:
    struct ScanResult {
        std::vector<PluginHandle> loaded;
        std::vector<LoadError> errors;
    };

    /// Scan plugin_dir, optionally verifying each plugin against an allowlist.
    /// If allowlist is non-empty, plugins whose hash doesn't match are rejected.
    [[nodiscard]] static ScanResult scan(
        const std::filesystem::path& plugin_dir,
        const std::unordered_map<std::string, std::string>& allowlist = {});
};

} // namespace yuzu::agent
