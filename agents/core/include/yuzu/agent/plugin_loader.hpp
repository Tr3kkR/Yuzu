#pragma once

#include <yuzu/plugin.h>

#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::agent {

struct LoadError {
    std::string path;
    std::string reason;
};

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
