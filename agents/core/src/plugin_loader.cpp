#include <yuzu/agent/plugin_loader.hpp>

#include <spdlog/spdlog.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  define YUZU_DLOPEN(p)       LoadLibraryW((p).wstring().c_str())
#  define YUZU_DLSYM(h, s)     GetProcAddress(static_cast<HMODULE>(h), s)
#  define YUZU_DLCLOSE(h)      FreeLibrary(static_cast<HMODULE>(h))
#  define YUZU_SO_EXT          ".dll"
#else
#  include <dlfcn.h>
#  define YUZU_DLOPEN(p)       dlopen((p).c_str(), RTLD_LAZY | RTLD_LOCAL)
#  define YUZU_DLSYM(h, s)     dlsym(h, s)
#  define YUZU_DLCLOSE(h)      dlclose(h)
#  ifdef __APPLE__
#    define YUZU_SO_EXT        ".dylib"
#  else
#    define YUZU_SO_EXT        ".so"
#  endif
#endif

namespace yuzu::agent {

// ── PluginHandle ──────────────────────────────────────────────────────────────

PluginHandle::PluginHandle(PluginHandle&& o) noexcept
    : handle_{o.handle_}, descriptor_{o.descriptor_}, path_{std::move(o.path_)} {
    o.handle_     = nullptr;
    o.descriptor_ = nullptr;
}

PluginHandle& PluginHandle::operator=(PluginHandle&& o) noexcept {
    if (this != &o) {
        if (handle_) YUZU_DLCLOSE(handle_);
        handle_     = o.handle_;
        descriptor_ = o.descriptor_;
        path_       = std::move(o.path_);
        o.handle_   = nullptr;
        o.descriptor_ = nullptr;
    }
    return *this;
}

PluginHandle::~PluginHandle() {
    if (handle_) {
        spdlog::debug("Unloading plugin: {}", path_);
        YUZU_DLCLOSE(handle_);
    }
}

std::expected<PluginHandle, LoadError>
PluginHandle::load(const std::filesystem::path& so_path) {
    spdlog::debug("Loading plugin: {}", so_path.string());

    void* handle = YUZU_DLOPEN(so_path);
    if (!handle) {
#ifdef _WIN32
        auto err = GetLastError();
        return std::unexpected(LoadError{so_path.string(),
            "LoadLibrary failed with error " + std::to_string(err)});
#else
        return std::unexpected(LoadError{so_path.string(), dlerror()});
#endif
    }

    auto* sym = reinterpret_cast<yuzu_plugin_descriptor_fn>(
        YUZU_DLSYM(handle, "yuzu_plugin_descriptor"));
    if (!sym) {
        YUZU_DLCLOSE(handle);
        return std::unexpected(LoadError{so_path.string(),
            "missing export 'yuzu_plugin_descriptor'"});
    }

    const YuzuPluginDescriptor* desc = sym();
    if (!desc) {
        YUZU_DLCLOSE(handle);
        return std::unexpected(LoadError{so_path.string(),
            "yuzu_plugin_descriptor() returned null"});
    }

    if (desc->abi_version != YUZU_PLUGIN_ABI_VERSION) {
        YUZU_DLCLOSE(handle);
        return std::unexpected(LoadError{so_path.string(),
            "ABI version mismatch: plugin=" + std::to_string(desc->abi_version) +
            " host=" + std::to_string(YUZU_PLUGIN_ABI_VERSION)});
    }

    PluginHandle ph;
    ph.handle_     = handle;
    ph.descriptor_ = desc;
    ph.path_       = so_path.string();
    return ph;
}

// ── PluginLoader ──────────────────────────────────────────────────────────────

PluginLoader::ScanResult PluginLoader::scan(const std::filesystem::path& plugin_dir) {
    ScanResult result;

    if (!std::filesystem::is_directory(plugin_dir)) {
        spdlog::warn("Plugin directory does not exist: {}", plugin_dir.string());
        return result;
    }

    for (const auto& entry : std::filesystem::directory_iterator(plugin_dir)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != YUZU_SO_EXT) continue;

        auto loaded = PluginHandle::load(entry.path());
        if (loaded) {
            spdlog::info("Loaded plugin: {} v{} from {}",
                loaded->descriptor()->name,
                loaded->descriptor()->version,
                loaded->path());
            result.loaded.push_back(std::move(*loaded));
        } else {
            spdlog::error("Failed to load plugin {}: {}",
                loaded.error().path, loaded.error().reason);
            result.errors.push_back(std::move(loaded.error()));
        }
    }

    return result;
}

}  // namespace yuzu::agent
