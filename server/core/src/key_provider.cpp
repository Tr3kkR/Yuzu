#include "key_provider.hpp"

#include <spdlog/spdlog.h>

#include <cstddef>
#include <fstream>
#include <random>
#include <system_error>

#ifndef _WIN32
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace yuzu::server {

namespace fs = std::filesystem;

namespace {

// A private key PEM is never legitimately large; cap it to bound a hostile or
// buggy caller (disk / memory DoS).
constexpr std::size_t kMaxKeyPemSize = 1024 * 1024;

// Set owner-only (0600) permissions on a file.
void set_owner_only_file(const fs::path& p) {
    std::error_code ec;
    fs::permissions(p, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace,
                    ec);
    if (ec)
        spdlog::warn("key_provider: could not set 0600 on {}: {}", p.string(), ec.message());
#ifdef _WIN32
    // POSIX bits are advisory on Windows; the data dir is created with a
    // restrictive ACL by the installer/service account, and the dedicated
    // service-account model (docs/agent-privilege-model.md) keeps the key
    // unreadable by `Everyone`. A native SetNamedSecurityInfo owner-only DACL
    // here is the cross-platform agent's follow-up (tracked for PR2 Windows
    // wiring); flagged in the PR1 security-review notes so it is not silently
    // assumed done.
#endif
}

// Collision-avoidance suffix for the temp file. NOT a security boundary —
// O_EXCL on create is what defeats a planted-path attack. Drawn straight from
// random_device (rather than a single-seeded mt19937_64) for better per-call
// entropy.
std::string random_suffix() {
    std::random_device rd;
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(32);
    for (int i = 0; i < 4; ++i) {
        uint32_t v = rd();
        for (int j = 0; j < 8; ++j) {
            s += kHex[v & 0xF];
            v >>= 4;
        }
    }
    return s;
}

} // namespace

FileKeyProvider::FileKeyProvider(fs::path base_dir) : base_dir_(std::move(base_dir)) {}

bool FileKeyProvider::is_safe_key_id(std::string_view key_id) {
    if (key_id.empty() || key_id.size() > 128)
        return false;
    if (key_id == "." || key_id == "..")
        return false;
    for (char c : key_id) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

bool FileKeyProvider::within_base(const fs::path& p) const {
    std::error_code ec;
    const fs::path base = fs::weakly_canonical(base_dir_, ec);
    if (ec)
        return false;
    const fs::path cand = fs::weakly_canonical(p, ec);
    if (ec)
        return false;
    // cand must start with base.
    auto bi = base.begin();
    auto ci = cand.begin();
    for (; bi != base.end(); ++bi, ++ci) {
        if (ci == cand.end() || *ci != *bi)
            return false;
    }
    return true;
}

fs::path FileKeyProvider::path_for(std::string_view key_id) const {
    return base_dir_ / (std::string(key_id) + ".key");
}

std::optional<std::string> FileKeyProvider::store_key(std::string_view key_id,
                                                      std::string_view pem) {
    if (!is_safe_key_id(key_id)) {
        spdlog::error("key_provider: rejected unsafe key_id '{}'", std::string(key_id));
        return std::nullopt;
    }
    if (pem.empty()) {
        spdlog::error("key_provider: refusing to store empty key '{}'", std::string(key_id));
        return std::nullopt;
    }
    if (pem.size() > kMaxKeyPemSize) {
        spdlog::error("key_provider: refusing oversized key '{}' ({} bytes)", std::string(key_id),
                      pem.size());
        return std::nullopt;
    }

    std::error_code ec;
    fs::create_directories(base_dir_, ec);
    if (ec) {
        spdlog::error("key_provider: cannot create {}: {}", base_dir_.string(), ec.message());
        return std::nullopt;
    }
    // Owner-only directory so the brief pre-chmod window on the temp file is not
    // exposed to other local users.
    fs::permissions(base_dir_, fs::perms::owner_all, fs::perm_options::replace, ec);

    const fs::path dest = path_for(key_id);
    const fs::path tmp = base_dir_ / (std::string(key_id) + ".key.tmp." + random_suffix());

#ifndef _WIN32
    {
        // Create the temp file mode 0600 from the outset — no umask window where
        // the private key is group/other-readable. O_EXCL refuses to reuse an
        // attacker-planted path.
        const int fd = ::open(tmp.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        if (fd < 0) {
            spdlog::error("key_provider: open temp {} failed: {}", tmp.string(),
                          std::strerror(errno));
            return std::nullopt;
        }
        const char* p = pem.data();
        std::size_t remaining = pem.size();
        bool ok = true;
        while (remaining > 0) {
            const ssize_t n = ::write(fd, p, remaining);
            if (n <= 0) {
                ok = false;
                break;
            }
            p += n;
            remaining -= static_cast<std::size_t>(n);
        }
        if (::close(fd) != 0)
            ok = false;
        if (!ok) {
            spdlog::error("key_provider: write failed for {}", tmp.string());
            fs::remove(tmp, ec);
            return std::nullopt;
        }
    }
#else
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            spdlog::error("key_provider: cannot open temp {}", tmp.string());
            return std::nullopt;
        }
        out.write(pem.data(), static_cast<std::streamsize>(pem.size()));
        out.flush();
        if (!out) {
            spdlog::error("key_provider: write failed for {}", tmp.string());
            out.close();
            fs::remove(tmp, ec);
            return std::nullopt;
        }
    }
#endif
    set_owner_only_file(tmp); // POSIX: re-assert; Windows: best-effort + ACL TODO (PR2)

    fs::rename(tmp, dest, ec); // same-directory rename is atomic on POSIX + Windows
    if (ec) {
        spdlog::error("key_provider: rename {} -> {} failed: {}", tmp.string(), dest.string(),
                      ec.message());
        fs::remove(tmp, ec);
        return std::nullopt;
    }
    set_owner_only_file(dest); // re-assert in case rename reset perms

    spdlog::info("key_provider: stored key '{}' (0600)", std::string(key_id));
    return dest.string();
}

std::optional<std::string> FileKeyProvider::load_key(std::string_view key_ref) {
    const fs::path p{key_ref};
    if (!within_base(p)) {
        spdlog::error("key_provider: refusing to load key_ref outside base: {}",
                      std::string(key_ref));
        return std::nullopt;
    }
    std::error_code sz_ec;
    const auto sz = fs::file_size(p, sz_ec);
    if (!sz_ec && sz > kMaxKeyPemSize) {
        spdlog::error("key_provider: key file {} too large ({} bytes)", p.string(), sz);
        return std::nullopt;
    }
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        spdlog::error("key_provider: cannot open key {}", p.string());
        return std::nullopt;
    }
    std::string pem((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (pem.empty()) {
        spdlog::error("key_provider: empty key file {}", p.string());
        return std::nullopt;
    }
    return pem;
}

bool FileKeyProvider::has_key(std::string_view key_ref) {
    const fs::path p{key_ref};
    if (!within_base(p))
        return false;
    std::error_code ec;
    return fs::exists(p, ec) && !ec;
}

bool FileKeyProvider::delete_key(std::string_view key_ref) {
    const fs::path p{key_ref};
    if (!within_base(p)) {
        spdlog::error("key_provider: refusing to delete key_ref outside base: {}",
                      std::string(key_ref));
        return false;
    }
    std::error_code rm_ec;
    fs::remove(p, rm_ec);
    std::error_code ex_ec;
    if (rm_ec && fs::exists(p, ex_ec)) {
        spdlog::error("key_provider: delete {} failed: {}", p.string(), rm_ec.message());
        return false;
    }
    return !fs::exists(p, ex_ec);
}

} // namespace yuzu::server
