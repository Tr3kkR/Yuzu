#pragma once

// cert_scan_collect.hpp -- home-directory discovery and filesystem walking
// for the cert_scan plugin.
//
// Directory walking itself is genuinely portable -- like pii_scan's own
// collector, std::filesystem::recursive_directory_iterator behaves the same
// on all three OSes -- so only home-directory DISCOVERY needs a per-OS
// branch (there is no portable API for "every local user's home
// directory"). Everything else in this header is shared code.
//
// Scope, deliberately, for v1:
//   - A per-file size cap and a per-scan file-count cap, same rationale as
//     pii_scan_collect.hpp: bound the blast radius of one scan invocation.
//   - A depth cap on the recursive walk (recursive_directory_iterator has
//     no cap of its own) -- an operator's home directory can contain
//     arbitrarily deep project trees (node_modules, vendored dependency
//     trees, etc.); the cap keeps one scan invocation's wall time bounded
//     without abandoning the walk outright.
//   - Symlinks are not followed -- recursive_directory_iterator's default
//     behaviour already refuses to descend into a symlinked directory
//     unless directory_options::follow_directory_symlink is explicitly
//     set (which this code never sets), so this is the iterator's own
//     built-in protection against symlink-cycle/escape attacks, not a
//     manual check this header adds on top.

#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include "user_profile_model.hpp"
#include "win_profiles.hpp"
#elif defined(__APPLE__)
#include <sys/stat.h>
#else
#include <sys/stat.h>
#endif

namespace yuzu::cert_scan {

struct ScanConfig {
    /// Operator-supplied directories to scan. Empty means "auto-discover
    /// every local user's home directory on this OS" (discover_home_directories()
    /// below) -- the plugin's default, no-parameters behaviour.
    std::vector<std::string> roots;
    std::size_t max_depth = 12;
    std::uint64_t max_file_size_bytes = 5ull * 1024 * 1024; // 5 MB -- keys/certs/containers are always small
    std::size_t max_files_per_scan = 50000;
};

struct CandidateFile {
    std::string path;
    std::uint64_t size_bytes = 0;
};

/// Extensions that make a file a scan candidate regardless of which
/// directory it's in. Lower-cased before lookup.
inline const std::unordered_set<std::string>& candidate_extensions() {
    static const std::unordered_set<std::string> kExtensions{
        ".pem", ".crt", ".cer", ".key", ".p12", ".pfx", ".jks", ".keystore", ".csr",
    };
    return kExtensions;
}

/// True when `path` is a scan candidate: either its extension is in
/// candidate_extensions(), or its immediate parent directory is named
/// ".ssh". The second arm exists because the single most common
/// private-key shape on disk -- OpenSSH's default `~/.ssh/id_rsa`,
/// `id_ed25519`, etc -- carries NO extension at all; an extension-only
/// allowlist would silently miss every default-named SSH key on the
/// filesystem, which is precisely the highest-value target this plugin
/// exists to find. Files under .ssh that aren't key material (known_hosts,
/// config, *.pub) are not excluded here -- they are naturally filtered out
/// downstream because cert_scan_rules.hpp's classify_content() finds no
/// recognizable marker in them and reports zero findings.
[[nodiscard]] inline bool is_candidate_file(const std::filesystem::path& p) {
    std::string ext = p.extension().string();
    for (char& c : ext)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (candidate_extensions().count(ext) > 0)
        return true;
    return p.has_parent_path() && p.parent_path().filename() == ".ssh";
}

/// Every real local user's home directory on this OS, auto-discovered with
/// no operator input. System/service accounts are excluded per-OS below.
/// Best-effort: a platform-specific enumeration failure yields an empty
/// vector (never a crash, never a fabricated path) -- enumerate_files()
/// then simply finds nothing to walk, which is an honest (if unhelpful)
/// outcome rather than a thrown exception reaching the plugin boundary.
[[nodiscard]] inline std::vector<std::string> discover_home_directories() {
    std::vector<std::string> out;

#ifdef _WIN32
    // Every local user profile via HKLM\...\ProfileList, same primitive
    // users_plugin.cpp/installed_apps_plugin.cpp/license_scan already use
    // for "every local user" enumeration. System SIDs (LocalSystem/
    // LocalService/NetworkService) are filtered before any path is used --
    // yuzu::profiles::is_system_sid mirrors tar_mapdrive_collector.cpp's
    // existing convention.
    bool ok = false;
    for (const auto& rec : yuzu::win::enumerate_profile_records(ok)) {
        if (yuzu::profiles::is_system_sid(rec.sid))
            continue;
        if (rec.profile_image_path.empty() || rec.profile_image_path_unreadable)
            continue;
        out.push_back(rec.profile_image_path);
    }
#elif defined(__APPLE__)
    // Every subdirectory of /Users except the two well-known non-personal
    // entries: "Shared" (a shared drop folder, not a user's home) and
    // "Guest" (the disabled-by-default guest account's placeholder home,
    // which macOS wipes on logout -- never worth scanning). No dscl/Open
    // Directory call: the directory NAME under /Users is used directly,
    // the same convention autoruns_macos.cpp's collect_user_launchagents
    // already establishes for this codebase (enumerate /Users, no
    // getpwuid()/OD lookup).
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(
             "/Users", std::filesystem::directory_options::skip_permission_denied, ec)) {
        if (ec)
            break;
        std::error_code is_dir_ec;
        if (!entry.is_directory(is_dir_ec) || is_dir_ec)
            continue;
        const std::string name = entry.path().filename().string();
        if (name == "Shared" || name == "Guest" || (!name.empty() && name.front() == '.'))
            continue;
        out.push_back(entry.path().string());
    }
#else
    // Linux: every subdirectory of /home, plus /root (the superuser's home
    // is not under /home and is worth including -- root-owned deployment
    // keys/certs are a real, common finding). No /etc/passwd uid-range
    // parsing: enumerating /home's own subdirectories directly mirrors
    // autoruns_linux.cpp's list_dir("/home") convention already
    // established in this codebase.
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(
             "/home", std::filesystem::directory_options::skip_permission_denied, ec)) {
        if (ec)
            break;
        std::error_code is_dir_ec;
        if (!entry.is_directory(is_dir_ec) || is_dir_ec)
            continue;
        out.push_back(entry.path().string());
    }
    struct stat root_st {};
    if (::stat("/root", &root_st) == 0 && S_ISDIR(root_st.st_mode))
        out.push_back("/root");
#endif

    return out;
}

/// Enumerates candidate files under all configured roots (or every
/// auto-discovered home directory, when config.roots is empty), applying
/// is_candidate_file(), the size cap, the depth cap, and the total-file-
/// count cap. Symlinks are not followed. Errors on an individual entry
/// (permission denied, races with a deleted file, etc.) are skipped rather
/// than aborting the whole walk -- a single unreadable file or directory
/// must not stop scanning the rest of a large home directory.
[[nodiscard]] inline std::vector<CandidateFile> enumerate_files(const ScanConfig& config) {
    std::vector<CandidateFile> out;

    const std::vector<std::string> roots =
        config.roots.empty() ? discover_home_directories() : config.roots;

    for (const auto& root : roots) {
        if (out.size() >= config.max_files_per_scan)
            break;

        std::error_code ec;
        std::filesystem::recursive_directory_iterator it(
            root, std::filesystem::directory_options::skip_permission_denied, ec);
        std::filesystem::recursive_directory_iterator end;
        if (ec)
            continue; // root doesn't exist / not readable -- skip, don't abort the whole scan

        for (; it != end && out.size() < config.max_files_per_scan; it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }

            if (static_cast<std::size_t>(it.depth()) >= config.max_depth) {
                it.disable_recursion_pending();
                // still evaluate this entry itself before the next
                // increment() stops descending further -- an entry AT the
                // depth cap is still a candidate, only its children are not.
            }

            if (it->is_symlink(ec) || ec) {
                ec.clear();
                continue;
            }
            if (!it->is_regular_file(ec) || ec) {
                ec.clear();
                continue;
            }

            const std::filesystem::path& p = it->path();
            if (!is_candidate_file(p))
                continue;

            std::uint64_t size = it->file_size(ec);
            if (ec) {
                ec.clear();
                continue;
            }
            if (size == 0 || size > config.max_file_size_bytes)
                continue;

            out.push_back(CandidateFile{p.string(), size});
        }
    }

    return out;
}

/// Reads a file's full content as raw bytes (up to `max_bytes`), binary-safe
/// (PKCS#12/JKS containers are not text). Returns nullopt on any I/O error
/// or size mismatch rather than a partial/garbage read.
[[nodiscard]] inline std::optional<std::string> read_file_bytes(const std::string& path,
                                                                 std::uint64_t max_bytes) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
        return std::nullopt;

    std::error_code ec;
    auto size = std::filesystem::file_size(path, ec);
    if (ec || size > max_bytes)
        return std::nullopt;

    std::ostringstream ss;
    ss << f.rdbuf();
    if (!f.good() && !f.eof())
        return std::nullopt;
    return ss.str();
}

} // namespace yuzu::cert_scan
