#include "key_provider.hpp"

#include "aes_gcm.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <spdlog/spdlog.h>

#include <cstddef>
#include <fstream>
#include <random>
#include <system_error>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
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

    const fs::path dest = path_for(key_id);
    if (!write_file_atomic(key_id, dest,
                           {reinterpret_cast<const std::uint8_t*>(pem.data()), pem.size()}))
        return std::nullopt;

    spdlog::info("key_provider: stored key '{}' (0600)", std::string(key_id));
    return dest.string();
}

bool FileKeyProvider::write_file_atomic(std::string_view key_id, const fs::path& dest,
                                        std::span<const std::uint8_t> bytes) {
    std::error_code ec;
    fs::create_directories(base_dir_, ec);
    if (ec) {
        spdlog::error("key_provider: cannot create {}: {}", base_dir_.string(), ec.message());
        return false;
    }
    // Owner-only directory so the brief pre-chmod window on the temp file is not
    // exposed to other local users.
    fs::permissions(base_dir_, fs::perms::owner_all, fs::perm_options::replace, ec);

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
            return false;
        }
        const std::uint8_t* p = bytes.data();
        std::size_t remaining = bytes.size();
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
        // fsync before rename (ADR-0010 §2 "Atomic write"): power loss after
        // the rename must never reveal a torn file that "resolves" but fails
        // every decrypt as pseudo-tamper.
        if (ok && ::fsync(fd) != 0)
            ok = false;
        if (::close(fd) != 0)
            ok = false;
        if (!ok) {
            spdlog::error("key_provider: write failed for {}", tmp.string());
            fs::remove(tmp, ec);
            return false;
        }
    }
#else
    {
        // CREATE_NEW = the O_EXCL analogue; FlushFileBuffers = the fsync
        // analogue. POSIX mode bits are an approximation on Windows — the
        // data dir carries a restrictive DACL granting only the service
        // account (docs/agent-privilege-model.md); the native owner-only
        // DACL remains the tracked follow-up flagged in the PR1 notes.
        const HANDLE h = ::CreateFileA(tmp.string().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                       FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            spdlog::error("key_provider: cannot open temp {} (err {})", tmp.string(),
                          ::GetLastError());
            return false;
        }
        const std::uint8_t* p = bytes.data();
        std::size_t remaining = bytes.size();
        bool ok = true;
        while (remaining > 0) {
            DWORD written = 0;
            const DWORD chunk = remaining > 0x0FFFFFFF ? 0x0FFFFFFF : static_cast<DWORD>(remaining);
            if (!::WriteFile(h, p, chunk, &written, nullptr) || written == 0) {
                ok = false;
                break;
            }
            p += written;
            remaining -= written;
        }
        if (ok && !::FlushFileBuffers(h))
            ok = false;
        if (!::CloseHandle(h))
            ok = false;
        if (!ok) {
            spdlog::error("key_provider: write failed for {}", tmp.string());
            fs::remove(tmp, ec);
            return false;
        }
    }
#endif
    set_owner_only_file(tmp); // POSIX: re-assert; Windows: best-effort + ACL TODO (PR2)

    fs::rename(tmp, dest, ec); // same-directory rename is atomic on POSIX + Windows
    if (ec) {
        spdlog::error("key_provider: rename {} -> {} failed: {}", tmp.string(), dest.string(),
                      ec.message());
        fs::remove(tmp, ec);
        return false;
    }
    set_owner_only_file(dest); // re-assert in case rename reset perms
    return true;
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
    {
        // Evict a cached KEK so a retired version cannot keep wrapping from
        // memory after its file is destroyed (ADR-0010 §3 retirement).
        std::lock_guard lock{kek_mutex_};
        if (auto it = kek_cache_.find(key_ref); it != kek_cache_.end())
            kek_cache_.erase(it); // SecureBuffer dtor cleanses
    }
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

// ── KEK wrap/unwrap seam (ADR-0010 §2) ───────────────────────────────────────

namespace {
constexpr std::size_t kKekSize = 32; // AES-256 KEK, raw bytes on disk
} // namespace

std::optional<std::string> FileKeyProvider::generate_kek(std::string_view key_id) {
    if (!is_safe_key_id(key_id)) {
        spdlog::error("key_provider: rejected unsafe kek key_id '{}'", std::string(key_id));
        return std::nullopt;
    }
    const fs::path dest = path_for(key_id);
    std::error_code ec;
    if (fs::exists(dest, ec)) {
        // Overwriting an existing KEK would orphan every blob wrapped under
        // it — a generation race or id-reuse bug must fail loudly, never
        // silently re-mint.
        spdlog::error("key_provider: refusing to overwrite existing KEK '{}'", std::string(key_id));
        return std::nullopt;
    }

    SecureBuffer kek{kKekSize};
    if (RAND_bytes(kek.data(), static_cast<int>(kek.size())) != 1) {
        // CSPRNG failure at generation is the startup_failed() class —
        // never fall back to a weaker source.
        spdlog::error("key_provider: RAND_bytes failed generating KEK '{}'", std::string(key_id));
        return std::nullopt;
    }
    if (!write_file_atomic(key_id, dest, kek.span()))
        return std::nullopt;

    std::string ref = dest.string();
    {
        std::lock_guard lock{kek_mutex_};
        kek_cache_.insert_or_assign(ref, std::move(kek));
    }
    spdlog::info("key_provider: generated KEK '{}' (0600, fsynced)", std::string(key_id));
    return ref;
}

std::optional<std::string> FileKeyProvider::resolve_kek(std::string_view key_id) {
    if (!is_safe_key_id(key_id))
        return std::nullopt;
    const fs::path p = path_for(key_id);
    std::error_code ec;
    if (!fs::exists(p, ec) || ec)
        return std::nullopt;
    return p.string();
}

const SecureBuffer* FileKeyProvider::kek_for_locked(std::string_view key_ref) {
    if (auto it = kek_cache_.find(key_ref); it != kek_cache_.end())
        return &it->second;

    const fs::path p{key_ref};
    if (!within_base(p)) {
        spdlog::error("key_provider: refusing KEK ref outside base: {}", std::string(key_ref));
        return nullptr;
    }
    std::error_code ec;
    const auto sz = fs::file_size(p, ec);
    if (ec || sz != kKekSize) {
        // Wrong size = torn/corrupt/absent. Unresolvable here; the
        // fingerprint check in SecretCodec::init() distinguishes
        // kek_corrupt from kek_unresolvable for the operator.
        spdlog::error("key_provider: KEK {} unreadable or not {} bytes", p.string(), kKekSize);
        return nullptr;
    }
    SecureBuffer kek{kKekSize};
    std::ifstream in(p, std::ios::binary);
    if (!in ||
        !in.read(reinterpret_cast<char*>(kek.data()), static_cast<std::streamsize>(kek.size()))) {
        spdlog::error("key_provider: cannot read KEK {}", p.string());
        return nullptr;
    }
    auto [it, inserted] = kek_cache_.insert_or_assign(std::string(key_ref), std::move(kek));
    return &it->second;
}

std::expected<WrappedDek, KekError>
FileKeyProvider::wrap_dek(std::string_view key_ref, std::span<const std::uint8_t, 32> dek,
                          std::span<const std::uint8_t> wrap_aad) {
    std::lock_guard lock{kek_mutex_};
    const SecureBuffer* kek = kek_for_locked(key_ref);
    if (kek == nullptr)
        return std::unexpected{KekError::unresolvable};

    WrappedDek out;
    if (RAND_bytes(out.nonce.data(), static_cast<int>(out.nonce.size())) != 1) {
        spdlog::error("key_provider: RAND_bytes failed minting wrap nonce");
        return std::unexpected{KekError::crypto_failure};
    }
    const auto rc =
        detail::aes256gcm_encrypt(std::span<const std::uint8_t, 32>{kek->data(), 32},
                                  std::span<const std::uint8_t, 12>{out.nonce}, wrap_aad, dek,
                                  out.wrapped.data(), std::span<std::uint8_t, 16>{out.tag});
    if (rc != detail::GcmResult::ok) {
        spdlog::error("key_provider: DEK wrap failed (EVP)");
        return std::unexpected{KekError::crypto_failure};
    }
    return out;
}

std::expected<SecureBuffer, KekError>
FileKeyProvider::unwrap_dek(std::string_view key_ref, const WrappedDek& wrapped,
                            std::span<const std::uint8_t> wrap_aad) {
    std::lock_guard lock{kek_mutex_};
    const SecureBuffer* kek = kek_for_locked(key_ref);
    if (kek == nullptr)
        return std::unexpected{KekError::unresolvable};

    SecureBuffer dek{kKekSize};
    const auto rc =
        detail::aes256gcm_decrypt(std::span<const std::uint8_t, 32>{kek->data(), 32},
                                  std::span<const std::uint8_t, 12>{wrapped.nonce}, wrap_aad,
                                  std::span<const std::uint8_t>{wrapped.wrapped},
                                  std::span<const std::uint8_t, 16>{wrapped.tag}, dek.data());
    switch (rc) {
    case detail::GcmResult::ok:
        return dek;
    case detail::GcmResult::auth_failed:
        // No spdlog here: the caller (SecretCodec) owns the audit event and
        // counter for tag failures — double-logging would let a systemic
        // class bury a genuine single-row tamper.
        return std::unexpected{KekError::tag_mismatch};
    case detail::GcmResult::error:
    default:
        spdlog::error("key_provider: DEK unwrap failed (EVP)");
        return std::unexpected{KekError::crypto_failure};
    }
}

std::optional<std::array<std::uint8_t, 32>>
FileKeyProvider::kek_check_value(std::string_view key_ref) {
    std::lock_guard lock{kek_mutex_};
    const SecureBuffer* kek = kek_for_locked(key_ref);
    if (kek == nullptr)
        return std::nullopt;
    // SHA-256 of the key material (ADR-0010 §2): safe for a full-entropy
    // 256-bit key — no dictionary angle. KCVs are non-secret.
    std::array<std::uint8_t, 32> kcv{};
    unsigned int md_len = 0;
    if (EVP_Digest(kek->data(), kek->size(), kcv.data(), &md_len, EVP_sha256(), nullptr) != 1 ||
        md_len != kcv.size()) {
        spdlog::error("key_provider: EVP_Digest failed computing KCV");
        return std::nullopt;
    }
    return kcv;
}

} // namespace yuzu::server
