#include <yuzu/agent/plugin_loader.hpp>

#include <spdlog/spdlog.h>

#include <fstream>
#include <sstream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#define YUZU_DLOPEN(p) LoadLibraryW((p).wstring().c_str())
#define YUZU_DLSYM(h, s) GetProcAddress(static_cast<HMODULE>(h), s)
#define YUZU_DLCLOSE(h) FreeLibrary(static_cast<HMODULE>(h))
#define YUZU_SO_EXT ".dll"
#else
#include <dlfcn.h>
#include <openssl/evp.h>
#define YUZU_DLOPEN(p) dlopen((p).c_str(), RTLD_LAZY | RTLD_LOCAL)
#define YUZU_DLSYM(h, s) dlsym(h, s)
#define YUZU_DLCLOSE(h) dlclose(h)
#ifdef __APPLE__
#define YUZU_SO_EXT ".dylib"
#else
#define YUZU_SO_EXT ".so"
#endif
#endif

namespace yuzu::agent {

// ── SHA-256 file hashing ─────────────────────────────────────────────────────

std::string sha256_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        spdlog::error("sha256_file: cannot open {}", path.string());
        return {};
    }

    constexpr size_t kBufSize = 64 * 1024;
    char buf[kBufSize];
    constexpr size_t kDigestLen = 32;
    unsigned char digest[kDigestLen]{};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return {};

    DWORD obj_size = 0, data_len = 0;
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_size),
                      sizeof(DWORD), &data_len, 0);
    std::vector<unsigned char> hash_obj(obj_size);
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, hash_obj.data(),
                                          static_cast<ULONG>(hash_obj.size()), nullptr, 0, 0))) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }

    while (f.read(buf, kBufSize) || f.gcount() > 0) {
        if (!BCRYPT_SUCCESS(BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf),
                                           static_cast<ULONG>(f.gcount()), 0))) {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            return {};
        }
        if (f.eof()) break;
    }

    bool ok = BCRYPT_SUCCESS(BCryptFinishHash(hash, digest, kDigestLen, 0));
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok) return {};
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        if (ctx) EVP_MD_CTX_free(ctx);
        return {};
    }

    while (f.read(buf, kBufSize) || f.gcount() > 0) {
        EVP_DigestUpdate(ctx, buf, static_cast<size_t>(f.gcount()));
        if (f.eof()) break;
    }

    unsigned int out_len = 0;
    bool ok = EVP_DigestFinal_ex(ctx, digest, &out_len) == 1 && out_len == kDigestLen;
    EVP_MD_CTX_free(ctx);
    if (!ok) return {};
#endif

    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(kDigestLen * 2);
    for (size_t i = 0; i < kDigestLen; ++i) {
        hex.push_back(kHex[digest[i] >> 4]);
        hex.push_back(kHex[digest[i] & 0x0F]);
    }
    return hex;
}

std::unordered_map<std::string, std::string>
load_plugin_allowlist(const std::filesystem::path& allowlist_path) {
    std::unordered_map<std::string, std::string> result;
    if (allowlist_path.empty() || !std::filesystem::exists(allowlist_path))
        return result;

    std::ifstream f(allowlist_path);
    if (!f) {
        spdlog::error("Cannot open plugin allowlist: {}", allowlist_path.string());
        return result;
    }

    std::string line;
    int lineno = 0;
    while (std::getline(f, line)) {
        ++lineno;
        if (line.empty() || line[0] == '#')
            continue;
        // Format: "hash  filename" or "hash filename" (sha256sum compatible)
        std::istringstream iss(line);
        std::string hash, filename;
        if (!(iss >> hash >> filename)) {
            spdlog::warn("Allowlist line {} malformed, skipping: {}", lineno, line);
            continue;
        }
        // Normalize hash to lowercase
        for (auto& c : hash)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        // Strip path prefix if present — match on filename only
        auto fname = std::filesystem::path(filename).filename().string();
        result[fname] = hash;
        spdlog::debug("Allowlist entry: {} -> {}", fname, hash);
    }

    spdlog::info("Loaded {} plugin allowlist entries from {}", result.size(),
                 allowlist_path.string());
    return result;
}

// ── PluginHandle ──────────────────────────────────────────────────────────────

PluginHandle::PluginHandle(PluginHandle&& o) noexcept
    : handle_{o.handle_}, descriptor_{o.descriptor_}, path_{std::move(o.path_)} {
    o.handle_ = nullptr;
    o.descriptor_ = nullptr;
}

PluginHandle& PluginHandle::operator=(PluginHandle&& o) noexcept {
    if (this != &o) {
        if (handle_)
            YUZU_DLCLOSE(handle_);
        handle_ = o.handle_;
        descriptor_ = o.descriptor_;
        path_ = std::move(o.path_);
        o.handle_ = nullptr;
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

std::expected<PluginHandle, LoadError> PluginHandle::load(const std::filesystem::path& so_path) {
    spdlog::debug("Loading plugin: {}", so_path.string());

    void* handle = YUZU_DLOPEN(so_path);
    if (!handle) {
#ifdef _WIN32
        auto err = GetLastError();
        return std::unexpected(
            LoadError{so_path.string(), "LoadLibrary failed with error " + std::to_string(err)});
#else
        return std::unexpected(LoadError{so_path.string(), dlerror()});
#endif
    }

    auto* sym =
        reinterpret_cast<yuzu_plugin_descriptor_fn>(YUZU_DLSYM(handle, "yuzu_plugin_descriptor"));
    if (!sym) {
        YUZU_DLCLOSE(handle);
        return std::unexpected(
            LoadError{so_path.string(), "missing export 'yuzu_plugin_descriptor'"});
    }

    const YuzuPluginDescriptor* desc = sym();
    if (!desc) {
        YUZU_DLCLOSE(handle);
        return std::unexpected(
            LoadError{so_path.string(), "yuzu_plugin_descriptor() returned null"});
    }

    if (desc->abi_version < YUZU_PLUGIN_ABI_VERSION_MIN || desc->abi_version > YUZU_PLUGIN_ABI_VERSION) {
        YUZU_DLCLOSE(handle);
        return std::unexpected(LoadError{
            so_path.string(), "ABI version mismatch: plugin=" + std::to_string(desc->abi_version) +
                                  " host_range=[" + std::to_string(YUZU_PLUGIN_ABI_VERSION_MIN) +
                                  "," + std::to_string(YUZU_PLUGIN_ABI_VERSION) + "]"});
    }

    PluginHandle ph;
    ph.handle_ = handle;
    ph.descriptor_ = desc;
    ph.path_ = so_path.string();
    return ph;
}

// ── PluginLoader ──────────────────────────────────────────────────────────────

PluginLoader::ScanResult PluginLoader::scan(
    const std::filesystem::path& plugin_dir,
    const std::unordered_map<std::string, std::string>& allowlist) {
    ScanResult result;

    if (!std::filesystem::is_directory(plugin_dir)) {
        spdlog::warn("Plugin directory does not exist: {}", plugin_dir.string());
        return result;
    }

    const bool enforce_allowlist = !allowlist.empty();
    if (enforce_allowlist) {
        spdlog::info("Plugin allowlist enforcement active ({} entries)", allowlist.size());
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(plugin_dir)) {
        if (!entry.is_regular_file())
            continue;
        if (entry.path().extension() != YUZU_SO_EXT)
            continue;

        // Allowlist verification: hash the file BEFORE dlopen
        if (enforce_allowlist) {
            auto fname = entry.path().filename().string();
            auto it = allowlist.find(fname);
            if (it == allowlist.end()) {
                spdlog::warn("Plugin {} not in allowlist — skipping", fname);
                result.errors.push_back(
                    LoadError{entry.path().string(), "not in plugin allowlist"});
                continue;
            }

            auto actual_hash = sha256_file(entry.path());
            if (actual_hash.empty()) {
                result.errors.push_back(
                    LoadError{entry.path().string(), "failed to compute SHA-256 hash"});
                continue;
            }

            if (actual_hash != it->second) {
                spdlog::error("Plugin {} hash mismatch: expected={}, actual={}",
                              fname, it->second, actual_hash);
                result.errors.push_back(
                    LoadError{entry.path().string(),
                              "SHA-256 hash mismatch (expected " + it->second +
                                  ", got " + actual_hash + ")"});
                continue;
            }
            spdlog::debug("Plugin {} hash verified: {}", fname, actual_hash);
        }

        auto loaded = PluginHandle::load(entry.path());
        if (loaded) {
            spdlog::info("Loaded plugin: {} v{} from {}", loaded->descriptor()->name,
                         loaded->descriptor()->version, loaded->path());
            result.loaded.push_back(std::move(*loaded));
        } else {
            spdlog::error("Failed to load plugin {}: {}", loaded.error().path,
                          loaded.error().reason);
            result.errors.push_back(std::move(loaded.error()));
        }
    }

    return result;
}

} // namespace yuzu::agent
