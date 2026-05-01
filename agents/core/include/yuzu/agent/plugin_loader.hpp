#pragma once

#include <yuzu/plugin.h>

#include <array>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
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

/// Stable reason prefixes for code-signing rejections. The metric label
/// derives from the prefix so operators can alert distinctly on
/// "no signature on plugin in require-mode" vs "bad signature" vs
/// "signature does not chain to a trusted CA".
inline constexpr std::string_view kSignatureMissingReason = "plugin signature missing";
inline constexpr std::string_view kSignatureInvalidReason = "plugin signature invalid";
inline constexpr std::string_view kSignatureUntrustedReason = "plugin signature untrusted chain";

/// Plugin code-signing trust anchor. When `trust_bundle_path` is non-empty,
/// PluginLoader::scan() looks for a sibling `<plugin-file>.sig` (PEM CMS
/// detached signature) for every candidate plugin. If a sig is present it
/// must verify against the bundle. If `require_signature` is true an
/// unsigned plugin is rejected; if false an unsigned plugin still loads
/// (allowlist still applies) — a transitional mode for operators rolling
/// out signing.
///
/// The trust bundle is a PEM file containing one or more X.509 root or
/// intermediate certificates. Today it is operator-supplied; once the
/// self-managed CA (auth-and-authz skill, Section 3 #10) ships the same
/// file path can point at the CA-published root.
struct PluginSigningPolicy {
    std::filesystem::path trust_bundle_path;
    bool require_signature{false};

    [[nodiscard]] bool enabled() const noexcept { return !trust_bundle_path.empty(); }
};

/// Verify a CMS detached PEM signature over the bytes of `plugin_path`,
/// chain-validating the embedded signing cert against the certs loaded
/// from `trust_bundle_path`. Returns std::nullopt on success; on failure
/// returns a stable reason prefix from kSignature*Reason that the loader
/// surfaces to the caller and metrics. Treat the return as "is bad" so
/// the call site reads as `if (auto err = verify_plugin_signature(...))`.
///
/// Sig file convention: same path as the plugin with `.sig` appended
/// (e.g. `chargen.so.sig`). PEM-armoured CMS so it inspects with
/// `openssl cms -inform pem -text -noout -in chargen.so.sig`.
[[nodiscard]] YUZU_EXPORT std::optional<std::string>
verify_plugin_signature(const std::filesystem::path& plugin_path,
                        const std::filesystem::path& trust_bundle_path);

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

    /// Scan plugin_dir, optionally verifying each plugin against an allowlist
    /// (sha256 integrity) and/or a code-signing trust anchor (CMS provenance).
    ///
    /// Verification order per file: allowlist (cheap, fail-fast) → signature
    /// (expensive). A plugin must clear *every* enabled check; the two layers
    /// answer different questions — allowlist binds *this filename to this
    /// hash on this host*, signing binds *this file content to a CA-issued
    /// signing identity*. Operators with internal builds typically enable
    /// both.
    [[nodiscard]] static ScanResult scan(
        const std::filesystem::path& plugin_dir,
        const std::unordered_map<std::string, std::string>& allowlist = {},
        const PluginSigningPolicy& signing = {});
};

} // namespace yuzu::agent
