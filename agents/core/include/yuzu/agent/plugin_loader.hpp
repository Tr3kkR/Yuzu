#pragma once

#include <yuzu/plugin.h>

#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace yuzu::agent {

struct LoadError {
    std::string path;
    std::string reason;
};

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

    [[nodiscard]] static ScanResult scan(const std::filesystem::path& plugin_dir);
};

} // namespace yuzu::agent
