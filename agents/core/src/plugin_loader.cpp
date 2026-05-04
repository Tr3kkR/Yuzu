#include <yuzu/agent/plugin_loader.hpp>

#include <spdlog/spdlog.h>

#include <fstream>
#include <sstream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#define YUZU_DLOPEN(p) LoadLibraryW((p).wstring().c_str())
#define YUZU_DLSYM(h, s) GetProcAddress(static_cast<HMODULE>(h), s)
#define YUZU_DLCLOSE(h) FreeLibrary(static_cast<HMODULE>(h))
#define YUZU_SO_EXT ".dll"
#else
#include <dlfcn.h>
#define YUZU_DLOPEN(p) dlopen((p).c_str(), RTLD_LAZY | RTLD_LOCAL)
#define YUZU_DLSYM(h, s) dlsym(h, s)
#define YUZU_DLCLOSE(h) dlclose(h)
#ifdef __APPLE__
#define YUZU_SO_EXT ".dylib"
#else
#define YUZU_SO_EXT ".so"
#endif
#endif

#include <openssl/bio.h>
// pem.h must come before cms.h so the PEM_*_CMS macros are declared
// (cms.h gates them on OPENSSL_PEM_H).
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

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

// ── Plugin code-signing verification ─────────────────────────────────────────
//
// Wire format:
//   * Signature file lives at `<plugin-path>.sig` (e.g. chargen.so.sig).
//   * Content is a PEM-armoured CMS detached signature, exactly what
//     `openssl cms -sign -binary -nodetach=false -outform PEM` produces.
//   * Trust anchor is a PEM file with one or more X.509 root/intermediate
//     certificates the operator chooses to trust. The bundle is
//     deployment-format-agnostic — it can hold a public CA root, an
//     internal-CA root, or (when shipped) the Yuzu self-managed CA root.
//
// What the verifier checks: CMS_verify with X509_V_FLAG inherits from the
// store. The store is built fresh per scan() call from the trust bundle.
// CMS_verify validates the embedded signing cert chain, the signature over
// the plugin file bytes, and basic cert validity (notBefore/notAfter,
// signature alg sanity). It does *not* fetch CRLs by default — CRL/OCSP
// integration is a future enhancement (issue follow-up).
//
// What the verifier does *not* claim: it does not bind the signature to
// the plugin filename. That binding is provided by the existing allowlist
// (which maps filename → expected SHA-256 of file content). When both
// allowlist and signature are enforced, an attacker cannot cross-replay
// signatures because: stolen-sig-on-different-file → CMS_verify fails
// (digest mismatch); stolen-sig-on-renamed-original → allowlist filename
// mismatch.

namespace {

struct OpenSslDeleter {
    void operator()(BIO* p) const noexcept { BIO_free_all(p); }
    void operator()(CMS_ContentInfo* p) const noexcept { CMS_ContentInfo_free(p); }
    void operator()(X509_STORE* p) const noexcept { X509_STORE_free(p); }
    void operator()(X509* p) const noexcept { X509_free(p); }
};

template <typename T>
using openssl_ptr = std::unique_ptr<T, OpenSslDeleter>;

// Drain the OpenSSL error queue into (text, classification). The
// classification flag is true if any drained error came from the
// X.509 chain validation path (CMS or X509 lib reporting cert-verify
// failure) — so the caller can pick between
// kSignatureUntrustedReason and kSignatureInvalidReason without
// re-parsing free-form text.
struct DrainedErrors {
    std::string text;
    bool chain_failure{false};
};

DrainedErrors drain_openssl_errors() {
    DrainedErrors out;
    char buf[256];
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        const int lib = ERR_GET_LIB(e);
        const int reason = ERR_GET_REASON(e);
        // ERR_LIB_CMS / CMS_R_CERTIFICATE_VERIFY_ERROR == 100
        // ERR_LIB_X509 covers all chain-validation surfaces.
        if (lib == ERR_LIB_X509 ||
            (lib == ERR_LIB_CMS && reason == CMS_R_CERTIFICATE_VERIFY_ERROR)) {
            out.chain_failure = true;
        }
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!out.text.empty()) out.text += "; ";
        out.text += buf;
    }
    return out;
}

openssl_ptr<X509_STORE> load_trust_store(const std::filesystem::path& bundle_path) {
    openssl_ptr<X509_STORE> store{X509_STORE_new()};
    if (!store) return nullptr;

    // X509_STORE_load_locations interprets a *file* parameter as one or
    // more concatenated PEM certs — exactly the format we promise the
    // operator. The third arg (path) lets OpenSSL also accept a hashed
    // dir; we only support a single bundle file today, so pass nullptr.
    if (X509_STORE_load_locations(store.get(), bundle_path.string().c_str(), nullptr) != 1) {
        spdlog::error("Failed to load plugin trust bundle '{}': {}",
                      bundle_path.string(), drain_openssl_errors().text);
        return nullptr;
    }
    // Plugin signing certs MUST carry EKU=codeSigning (RFC 5280 §4.2.1.12).
    // Setting the X509_STORE purpose forces OpenSSL to enforce the EKU
    // during chain validation. A leaf without codeSigning EKU — e.g. an
    // mTLS server cert, S/MIME cert, or TLS client cert minted by the
    // *same* CA the operator trusts — is rejected. Without this, a
    // single CA whose downstream issues a non-code-signing cert (very
    // common in internal PKIs that issue mTLS + S/MIME from one root)
    // becomes a plugin-signing authority too. Fixed in governance
    // hardening round 1 (sec-LOW-2 / UP-8).
    if (X509_STORE_set_purpose(store.get(), X509_PURPOSE_CODE_SIGN) != 1) {
        spdlog::error("Failed to set X509 purpose to codeSigning: {}",
                      drain_openssl_errors().text);
        return nullptr;
    }
    return store;
}

} // namespace

std::optional<std::string>
verify_plugin_signature(const std::filesystem::path& plugin_path,
                        const std::filesystem::path& trust_bundle_path) {
    auto sig_path = plugin_path;
    sig_path += ".sig";

    std::error_code ec;
    if (!std::filesystem::exists(sig_path, ec)) {
        return std::string{kSignatureMissingReason};
    }

    auto store = load_trust_store(trust_bundle_path);
    if (!store) {
        // Bundle path unreadable → we cannot prove anything, refuse to
        // trust. Operator misconfiguration must surface, not silently
        // pass plugins through.
        return std::string{kSignatureUntrustedReason} + ": trust bundle unreadable";
    }

    openssl_ptr<BIO> sig_bio{BIO_new_file(sig_path.string().c_str(), "rb")};
    if (!sig_bio) {
        const auto err = drain_openssl_errors();
        return std::string{kSignatureInvalidReason} + ": cannot open signature file: " +
               err.text;
    }

    openssl_ptr<CMS_ContentInfo> cms{
        PEM_read_bio_CMS(sig_bio.get(), nullptr, nullptr, nullptr)};
    if (!cms) {
        const auto err = drain_openssl_errors();
        return std::string{kSignatureInvalidReason} + ": malformed PEM CMS: " + err.text;
    }

    openssl_ptr<BIO> content_bio{BIO_new_file(plugin_path.string().c_str(), "rb")};
    if (!content_bio) {
        const auto err = drain_openssl_errors();
        return std::string{kSignatureInvalidReason} + ": cannot open plugin file: " +
               err.text;
    }

    // Single CMS_verify does both checks atomically:
    //   * chain-validates each signer cert against the trust store
    //     (purpose was set to CODE_SIGN in load_trust_store so any leaf
    //     without EKU=codeSigning is rejected — even if the leaf chains
    //     to a CA the operator trusts).
    //   * verifies the signature digest over the detached payload.
    //   * CMS_BINARY suppresses CRLF canonicalisation we do not want on
    //     a binary payload.
    //   * MUST NOT pass CMS_NO_SIGNER_CERT_VERIFY or CMS_NO_CONTENT_VERIFY
    //     — those flags individually disable the chain check or the
    //     digest check and would silently weaken the verifier. Pinning
    //     the policy here as a load-bearing invariant for future edits
    //     (governance hardening round 1, sec-INFO-8).
    if (CMS_verify(cms.get(), nullptr, store.get(), content_bio.get(), nullptr,
                   CMS_BINARY | CMS_DETACHED) != 1) {
        const auto err = drain_openssl_errors();
        const std::string_view prefix =
            err.chain_failure ? kSignatureUntrustedReason : kSignatureInvalidReason;
        return std::string{prefix} + ": " + err.text;
    }

    // Drain any benign residual error-queue entries from the success
    // path so a httplib worker thread that handles a /tls call after
    // this one does not see stale OpenSSL errors. PEM_read_bio_X509 +
    // friends push end-of-stream sentinels onto the thread-local queue
    // even on success (cpp-S5 / sec-LOW-6).
    ERR_clear_error();
    return std::nullopt; // verified
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

    // ABI v3+ includes sdk_version for diagnostics
    const char* sdk_ver = (desc->abi_version >= 3 && desc->sdk_version) ? desc->sdk_version : "unknown";
    spdlog::info("Loaded plugin '{}' v{} (ABI={}, SDK={})", desc->name, desc->version,
                 desc->abi_version, sdk_ver);

    PluginHandle ph;
    ph.handle_ = handle;
    ph.descriptor_ = desc;
    ph.path_ = so_path.string();
    return ph;
}

// ── PluginLoader ──────────────────────────────────────────────────────────────

PluginLoader::ScanResult PluginLoader::scan(
    const std::filesystem::path& plugin_dir,
    const std::unordered_map<std::string, std::string>& allowlist,
    const PluginSigningPolicy& signing) {
    ScanResult result;

    if (!std::filesystem::is_directory(plugin_dir)) {
        spdlog::warn("Plugin directory does not exist: {}", plugin_dir.string());
        return result;
    }

    const bool enforce_allowlist = !allowlist.empty();
    const bool enforce_signing = signing.enabled();
    if (enforce_allowlist) {
        spdlog::info("Plugin allowlist enforcement active ({} entries)", allowlist.size());
    }
    if (enforce_signing) {
        spdlog::info("Plugin code-signing enforcement active (trust bundle '{}', require={})",
                     signing.trust_bundle_path.string(), signing.require_signature);
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

        // Code-signing verification — runs after allowlist (cheap-fail-first)
        // and before dlopen so a malformed/sig-bad library is never mapped.
        // Two-mode contract:
        //   * require_signature=true  → no sig OR bad sig = reject
        //   * require_signature=false → no sig is allowed (transitional);
        //     a sig file present must still verify or the plugin is
        //     rejected (defence against attacker-supplied malicious .sig).
        if (enforce_signing) {
            auto sig_path = entry.path();
            sig_path += ".sig";
            const bool sig_present = std::filesystem::exists(sig_path);
            if (!sig_present && !signing.require_signature) {
                spdlog::debug("Plugin {} has no signature (require=false), allowing",
                              entry.path().filename().string());
            } else {
                auto err = verify_plugin_signature(entry.path(), signing.trust_bundle_path);
                if (err) {
                    spdlog::error("Plugin {} signature rejected: {}",
                                  entry.path().string(), *err);
                    result.errors.push_back(
                        LoadError{entry.path().string(), std::move(*err)});
                    continue;
                }
                spdlog::info("Plugin {} signature verified", entry.path().filename().string());
            }
        }

        // Symlink check: reject symlinks to prevent directory traversal attacks
        if (std::filesystem::is_symlink(entry.path())) {
            spdlog::warn("Plugin {} is a symlink — skipping", entry.path().string());
            result.errors.push_back(
                LoadError{entry.path().string(), "symlinks not allowed in plugin directory"});
            continue;
        }

        auto loaded = PluginHandle::load(entry.path());
        if (loaded) {
            const std::string_view plugin_name{loaded->descriptor()->name};
            if (is_reserved_plugin_name(plugin_name)) {
                // #453: prevent a compromised plugin author from shadowing
                // the Guardian (__guard__) or other reserved dispatch names.
                // The handle destructs here and dlcloses the library.
                spdlog::error(
                    "Plugin {} declares reserved name '{}' — rejecting to protect internal dispatch",
                    entry.path().string(), plugin_name);
                result.errors.push_back(LoadError{
                    entry.path().string(),
                    std::string{kReservedNameReason} + ": '" + std::string{plugin_name} + "'"});
                continue;
            }
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
