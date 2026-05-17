/**
 * updater.cpp — Agent-side OTA update: check, download, verify, self-replace
 *
 * Implements the Updater class declared in <yuzu/agent/updater.hpp>.
 * Uses platform-specific crypto for SHA-256 (BCrypt on Windows, OpenSSL EVP
 * on POSIX) and platform-specific filesystem operations for atomic binary
 * replacement with rollback support.
 */

#include <yuzu/agent/updater.hpp>

// Generated protobuf/gRPC headers (flat output from YuzuProto.cmake)
#include "agent.grpc.pb.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <new> // std::launder
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <windows.h>  // must precede bcrypt.h (defines NTSTATUS)
// clang-format on
#include <bcrypt.h>
#include <sddl.h>
#include <cstddef> // offsetof
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#else
#include <openssl/evp.h>
// W2.3 / #806: POSIX fd-pin across hash → rename. mkstemps directly
// returns an open fd we hold through apply_update; fstat/stat compare
// detects a path-swap attack before the rename consumes the path.
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h> // _NSGetExecutablePath
#endif
#endif

namespace yuzu::agent {

namespace {

namespace pb = ::yuzu::agent::v1;

// ── SHA-256 incremental hasher ─────────────────────────────────────────────

class Sha256Hasher {
public:
    Sha256Hasher() {
#ifdef _WIN32
        NTSTATUS status = BCryptOpenAlgorithmProvider(&alg_, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            spdlog::error("BCryptOpenAlgorithmProvider failed: 0x{:08x}",
                          static_cast<unsigned>(status));
            valid_ = false;
            return;
        }

        DWORD obj_size = 0;
        DWORD data_len = 0;
        status = BCryptGetProperty(alg_, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_size),
                                   sizeof(DWORD), &data_len, 0);
        if (!BCRYPT_SUCCESS(status)) {
            spdlog::error("BCryptGetProperty failed: 0x{:08x}", static_cast<unsigned>(status));
            BCryptCloseAlgorithmProvider(alg_, 0);
            valid_ = false;
            return;
        }

        hash_obj_.resize(obj_size);
        status = BCryptCreateHash(alg_, &hash_, hash_obj_.data(),
                                  static_cast<ULONG>(hash_obj_.size()), nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(status)) {
            spdlog::error("BCryptCreateHash failed: 0x{:08x}", static_cast<unsigned>(status));
            BCryptCloseAlgorithmProvider(alg_, 0);
            valid_ = false;
            return;
        }
        valid_ = true;
#else
        ctx_ = EVP_MD_CTX_new();
        if (!ctx_ || EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr) != 1) {
            spdlog::error("EVP_DigestInit_ex failed");
            if (ctx_) {
                EVP_MD_CTX_free(ctx_);
                ctx_ = nullptr;
            }
            valid_ = false;
            return;
        }
        valid_ = true;
#endif
    }

    ~Sha256Hasher() {
#ifdef _WIN32
        if (hash_)
            BCryptDestroyHash(hash_);
        if (alg_)
            BCryptCloseAlgorithmProvider(alg_, 0);
#else
        if (ctx_)
            EVP_MD_CTX_free(ctx_);
#endif
    }

    Sha256Hasher(const Sha256Hasher&) = delete;
    Sha256Hasher& operator=(const Sha256Hasher&) = delete;

    [[nodiscard]] bool is_valid() const noexcept { return valid_; }

    bool update(const void* data, size_t len) {
        if (!valid_)
            return false;
#ifdef _WIN32
        NTSTATUS status = BCryptHashData(hash_, static_cast<PUCHAR>(const_cast<void*>(data)),
                                         static_cast<ULONG>(len), 0);
        return BCRYPT_SUCCESS(status);
#else
        return EVP_DigestUpdate(ctx_, data, len) == 1;
#endif
    }

    /// Finalize and return lowercase hex-encoded SHA-256 digest.
    [[nodiscard]] std::string finalize() {
        if (!valid_)
            return {};

        constexpr size_t kDigestLen = 32; // SHA-256 = 256 bits = 32 bytes
        unsigned char digest[kDigestLen]{};

#ifdef _WIN32
        NTSTATUS status = BCryptFinishHash(hash_, digest, kDigestLen, 0);
        if (!BCRYPT_SUCCESS(status)) {
            spdlog::error("BCryptFinishHash failed: 0x{:08x}", static_cast<unsigned>(status));
            return {};
        }
#else
        unsigned int out_len = 0;
        if (EVP_DigestFinal_ex(ctx_, digest, &out_len) != 1 || out_len != kDigestLen) {
            spdlog::error("EVP_DigestFinal_ex failed");
            return {};
        }
#endif

        // Convert to lowercase hex
        static constexpr char kHex[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(kDigestLen * 2);
        for (size_t i = 0; i < kDigestLen; ++i) {
            hex.push_back(kHex[digest[i] >> 4]);
            hex.push_back(kHex[digest[i] & 0x0F]);
        }
        return hex;
    }

private:
    bool valid_{false};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg_{nullptr};
    BCRYPT_HASH_HANDLE hash_{nullptr};
    std::vector<unsigned char> hash_obj_;
#else
    EVP_MD_CTX* ctx_{nullptr};
#endif
};

/// Case-insensitive string equality.
bool iequal(std::string_view a, std::string_view b) {
    if (a.size() != b.size())
        return false;
    return std::ranges::equal(a, b, [](char lhs, char rhs) {
        return std::tolower(static_cast<unsigned char>(lhs)) ==
               std::tolower(static_cast<unsigned char>(rhs));
    });
}

} // anonymous namespace

// ── current_executable_path ────────────────────────────────────────────────

std::filesystem::path current_executable_path() {
#ifdef _WIN32
    wchar_t buf[MAX_PATH]{};
    DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        spdlog::error("GetModuleFileNameW failed: {}", GetLastError());
        return {};
    }
    return std::filesystem::path{buf};
#elif defined(__APPLE__)
    char buf[4096]{};
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) != 0) {
        spdlog::error("_NSGetExecutablePath failed (buffer too small, need {} bytes)", size);
        return {};
    }
    std::error_code ec;
    auto result = std::filesystem::canonical(buf, ec);
    if (ec) {
        spdlog::error("canonical() failed for '{}': {}", buf, ec.message());
        return {};
    }
    return result;
#else
    // Linux
    std::error_code ec;
    auto result = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (ec) {
        spdlog::error("read_symlink(/proc/self/exe) failed: {}", ec.message());
        return {};
    }
    return result;
#endif
}

// ── Updater ────────────────────────────────────────────────────────────────

// Semantic version comparison: returns -1 if a < b, 0 if equal, 1 if a > b.
// Strips leading 'v' and handles up to 3 numeric components (major.minor.patch).
int compare_semver(std::string_view a, std::string_view b) {
    auto parse = [](std::string_view s) -> std::array<int, 3> {
        std::array<int, 3> parts{0, 0, 0};
        if (!s.empty() && (s[0] == 'v' || s[0] == 'V'))
            s.remove_prefix(1);
        // Strip pre-release suffix (e.g., "-rc1")
        auto dash = s.find('-');
        if (dash != std::string_view::npos)
            s = s.substr(0, dash);
        for (int i = 0; i < 3 && !s.empty(); ++i) {
            auto dot = s.find('.');
            auto part = s.substr(0, dot);
            int val = 0;
            std::from_chars(part.data(), part.data() + part.size(), val);
            parts[i] = val;
            if (dot == std::string_view::npos)
                break;
            s.remove_prefix(dot + 1);
        }
        return parts;
    };
    auto pa = parse(a);
    auto pb = parse(b);
    for (int i = 0; i < 3; ++i) {
        if (pa[i] < pb[i])
            return -1;
        if (pa[i] > pb[i])
            return 1;
    }
    return 0;
}

constexpr int64_t kMaxDownloadBytes = 512 * 1024 * 1024; // 512 MiB hard cap

Updater::Updater(UpdateConfig config, std::string agent_id, std::string current_version,
                 std::string os, std::string arch, std::filesystem::path exe_path)
    : config_{std::move(config)}, agent_id_{std::move(agent_id)},
      current_version_{std::move(current_version)}, os_{std::move(os)}, arch_{std::move(arch)},
      exe_path_{std::move(exe_path)} {}

void Updater::stop() noexcept {
    stop_requested_.store(true, std::memory_order_release);
}

std::expected<bool, UpdateError> Updater::check_and_apply(void* raw_stub) {
    if (!raw_stub) {
        return std::unexpected(UpdateError{"null gRPC stub"});
    }

    if (!config_.enabled) {
        spdlog::debug("OTA updates disabled by config");
        return false;
    }

    if (stop_requested_.load(std::memory_order_acquire)) {
        return false;
    }

    auto* stub = static_cast<pb::AgentService::Stub*>(raw_stub);

    // ── Step 1: Check for update ───────────────────────────────────────────

    pb::CheckForUpdateRequest check_req;
    check_req.set_agent_id(agent_id_);
    check_req.set_current_version(current_version_);
    auto* platform = check_req.mutable_platform();
    platform->set_os(os_);
    platform->set_arch(arch_);

    grpc::ClientContext check_ctx;
    pb::CheckForUpdateResponse check_resp;
    grpc::Status check_status = stub->CheckForUpdate(&check_ctx, check_req, &check_resp);

    if (!check_status.ok()) {
        return std::unexpected(UpdateError{
            std::format("CheckForUpdate RPC failed: {} (code {})", check_status.error_message(),
                        static_cast<int>(check_status.error_code()))});
    }

    if (!check_resp.update_available()) {
        spdlog::debug("No update available (current: {})", current_version_);
        return false;
    }

    if (!check_resp.eligible()) {
        spdlog::info("Update {} available but agent is not eligible for rollout",
                     check_resp.latest_version());
        return false;
    }

    // Downgrade protection: reject versions older than current
    if (compare_semver(check_resp.latest_version(), current_version_) <= 0) {
        spdlog::warn("Rejected update {} — not newer than current {} (downgrade blocked)",
                     check_resp.latest_version(), current_version_);
        return false;
    }

    spdlog::info("Update available: {} -> {} ({} bytes, mandatory={})", current_version_,
                 check_resp.latest_version(), check_resp.file_size(), check_resp.mandatory());

    if (stop_requested_.load(std::memory_order_acquire)) {
        return false;
    }

    // ── Step 2: Create temp file for download ──────────────────────────────
    //
    // POSIX (W2.3 / #806): use mkstemps directly so we retain the open fd
    // across the download + hash + apply_update flow. The previous
    // `yuzu_create_temp_file` helper opens-then-closes the fd, leaving a
    // race window where an attacker with write access to the system temp
    // directory can swap the temp file content between our SHA-256 check
    // and the subsequent rename — at which point the agent would copy the
    // attacker's bytes over its own executable. We close the fd only
    // AFTER apply_update returns and AFTER a final inode-equivalence check
    // against the on-disk path.
    //
    // Windows (W2.3 cross-platform-debt closure): CreateFileW with
    // dwShareMode=0 + DELETE access, held across hash → rename. The held
    // HANDLE makes the temp file unwritable, undeletable, and unrenamable
    // by anyone else (no SHARE_WRITE, no SHARE_DELETE), and the final
    // `SetFileInformationByHandle(FileRenameInfo)` atomically renames the
    // inode the HANDLE points at — no path resolution between hash and
    // rename, so the attack window present in the close-then-rename flow
    // is fully closed. Temp file is created in exe_path_.parent_path()
    // because FileRenameInfo requires same-volume source and destination.

    std::filesystem::path temp_path;
#ifndef _WIN32
    struct ScopedFd {
        int fd = -1;
        ~ScopedFd() {
            if (fd >= 0)
                ::close(fd);
        }
    } fd_guard;
    {
        std::error_code ec;
        auto temp_dir = std::filesystem::temp_directory_path(ec);
        if (ec) {
            return std::unexpected(
                UpdateError{std::format("Failed to resolve temp directory: {}", ec.message())});
        }
        std::string tmpl = (temp_dir / "yuzu-update-XXXXXX.tmp").string();
        // mkstemps suffix length: ".tmp" = 4
        fd_guard.fd = ::mkstemps(tmpl.data(), 4);
        if (fd_guard.fd < 0) {
            return std::unexpected(
                UpdateError{std::format("mkstemps failed: {}", std::strerror(errno))});
        }
        temp_path = tmpl;
    }
#else
    struct ScopedHandle {
        HANDLE h = INVALID_HANDLE_VALUE;
        ScopedHandle() = default;
        ~ScopedHandle() {
            if (h != INVALID_HANDLE_VALUE)
                CloseHandle(h);
        }
        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;
        ScopedHandle(ScopedHandle&&) = delete;
        ScopedHandle& operator=(ScopedHandle&&) = delete;
    } h_guard;
    {
        // Same-volume requirement: FileRenameInfo will not cross volumes.
        // Placing the temp next to exe_path_ also keeps the download out
        // of the world-writable system temp (defense-in-depth against the
        // very attack we're closing). Resolve to absolute first so an
        // operator launching with a bare argv[0] doesn't land on an empty
        // parent_path.
        std::error_code abs_ec;
        auto abs_exe = std::filesystem::absolute(exe_path_, abs_ec);
        if (abs_ec) {
            return std::unexpected(
                UpdateError{std::format("Failed to resolve absolute exe path '{}': {}",
                                        exe_path_.string(), abs_ec.message())});
        }
        auto temp_dir = abs_exe.parent_path();
        std::error_code dir_ec;
        if (temp_dir.empty() || !std::filesystem::exists(temp_dir, dir_ec)) {
            return std::unexpected(UpdateError{std::format(
                "exe parent dir '{}' does not exist; cannot stage update", temp_dir.string())});
        }

        UCHAR rand_bytes[16];
        NTSTATUS rnd_status = BCryptGenRandom(nullptr, rand_bytes, sizeof(rand_bytes),
                                              BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(rnd_status)) {
            return std::unexpected(
                UpdateError{std::format("BCryptGenRandom for temp filename failed: 0x{:08x}",
                                        static_cast<unsigned>(rnd_status))});
        }
        char hex[33]{};
        for (int i = 0; i < 16; ++i) {
            std::snprintf(hex + i * 2, 3, "%02x", rand_bytes[i]);
        }
        temp_path = temp_dir / (std::string{"yuzu-update-"} + hex + ".tmp");

        // Owner-only DACL is defence-in-depth — it prevents non-owner readers
        // from opening the temp file. The load-bearing defence against the
        // close-then-rename race is dwShareMode=0 below, which makes the
        // HANDLE exclusive: nobody else can open the temp file for read,
        // write, or delete while we hold it.
        SECURITY_ATTRIBUTES sa{};
        PSECURITY_DESCRIPTOR sd = nullptr;
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;OW)",
                                                                  SDDL_REVISION_1, &sd, nullptr)) {
            return std::unexpected(UpdateError{
                std::format("ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                            GetLastError())});
        }
        sa.lpSecurityDescriptor = sd;

        h_guard.h = CreateFileW(temp_path.wstring().c_str(),
                                GENERIC_WRITE | DELETE, // DELETE required for FileRenameInfo*
                                0, // No sharing — load-bearing exclusive hold
                                &sa,
                                CREATE_NEW, // Atomic create; fail if exists
                                FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (sd)
            LocalFree(sd);

        if (h_guard.h == INVALID_HANDLE_VALUE) {
            return std::unexpected(
                UpdateError{std::format("CreateFileW for update temp file '{}' failed: {}",
                                        temp_path.string(), GetLastError())});
        }
    }
#endif

    // ── Step 3: Download the update binary ─────────────────────────────────

    pb::DownloadUpdateRequest dl_req;
    dl_req.set_agent_id(agent_id_);
    dl_req.set_version(check_resp.latest_version());
    auto* dl_platform = dl_req.mutable_platform();
    dl_platform->set_os(os_);
    dl_platform->set_arch(arch_);

    grpc::ClientContext dl_ctx;
    auto reader = stub->DownloadUpdate(&dl_ctx, dl_req);

    // Cleanup helper: on Windows the path-based fs::remove fails with
    // ERROR_SHARING_VIOLATION while h_guard holds the file with dwShareMode=0,
    // so we mark the file for delete-on-close via FileDispositionInfo — the
    // RAII CloseHandle in ~ScopedHandle then deletes it for free. On POSIX
    // unlink-while-open is fine, so fs::remove still works.
    auto cleanup_temp = [&] {
#ifdef _WIN32
        FILE_DISPOSITION_INFO di{};
        di.DeleteFile = TRUE;
        SetFileInformationByHandle(h_guard.h, FileDispositionInfo, &di, sizeof(di));
#else
        std::error_code ec;
        std::filesystem::remove(temp_path, ec);
#endif
    };

    Sha256Hasher hasher;
    if (!hasher.is_valid()) {
        cleanup_temp();
        return std::unexpected(UpdateError{"Failed to initialize SHA-256 hasher"});
    }

    int64_t bytes_downloaded = 0;
    pb::DownloadUpdateChunk chunk;

    auto cleanup_and_fail = [&](const std::string& msg) -> std::expected<bool, UpdateError> {
        cleanup_temp();
        return std::unexpected(UpdateError{msg});
    };

    while (reader->Read(&chunk)) {
        if (stop_requested_.load(std::memory_order_acquire)) {
            cleanup_temp();
            return false;
        }

        const auto& data = chunk.data();
#ifndef _WIN32
        // write(fd) may return short. Loop until all bytes are written or
        // we hit a real error. EINTR is retried; other errors abort.
        const char* p = data.data();
        std::size_t remaining = data.size();
        while (remaining > 0) {
            ssize_t n = ::write(fd_guard.fd, p, remaining);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                return cleanup_and_fail(
                    std::format("write to temp fd failed: {}", std::strerror(errno)));
            }
            p += n;
            remaining -= static_cast<std::size_t>(n);
        }
#else
        // WriteFile to the held HANDLE — no std::ofstream re-open, so the
        // close-then-rename race window is gone. Short writes loop until
        // all bytes are committed or a real error fires.
        const char* p = data.data();
        DWORD remaining = static_cast<DWORD>(data.size());
        while (remaining > 0) {
            DWORD written = 0;
            if (!WriteFile(h_guard.h, p, remaining, &written, nullptr)) {
                return cleanup_and_fail(
                    std::format("WriteFile to update temp handle failed: {}", GetLastError()));
            }
            if (written == 0) {
                return cleanup_and_fail("WriteFile returned 0 bytes — disk full or quota?");
            }
            p += written;
            remaining -= written;
        }
#endif

        if (!hasher.update(data.data(), data.size())) {
            return cleanup_and_fail("SHA-256 hash update failed during download");
        }

        bytes_downloaded += static_cast<int64_t>(data.size());
        if (bytes_downloaded > kMaxDownloadBytes) {
            return cleanup_and_fail(std::format("Download exceeds maximum size ({} MiB)",
                                                kMaxDownloadBytes / (1024 * 1024)));
        }
    }

    grpc::Status dl_status = reader->Finish();
#ifdef _WIN32
    // FlushFileBuffers is the Windows analog of fsync — guarantees the
    // bytes we hashed are on disk before the rename. Non-fatal on failure
    // (the page cache will still service the rename atomically).
    if (!FlushFileBuffers(h_guard.h)) {
        spdlog::warn("FlushFileBuffers on update temp handle failed (non-fatal): {}",
                     GetLastError());
    }
#else
    // Flush the fd to disk before the rename so the on-disk content matches
    // what we hashed. fsync failure is non-fatal (the bytes still land via
    // page cache on rename) but logged.
    if (::fsync(fd_guard.fd) < 0) {
        spdlog::warn("fsync on update temp fd failed (non-fatal): {}", std::strerror(errno));
    }
#endif

    if (!dl_status.ok()) {
        cleanup_temp();
        return std::unexpected(UpdateError{std::format("DownloadUpdate RPC failed: {} (code {})",
                                                       dl_status.error_message(),
                                                       static_cast<int>(dl_status.error_code()))});
    }

    spdlog::info("Downloaded {} bytes for update {}", bytes_downloaded,
                 check_resp.latest_version());

    // ── Step 4: Verify SHA-256 ─────────────────────────────────────────────
    //
    // The hash is computed streaming from the bytes we wrote, NOT from a
    // re-read of the file. So `actual_hash` covers what the fd/HANDLE holds,
    // not what is currently at `temp_path` on disk — on POSIX those can
    // diverge if a local attacker raced us during the write loop, and the
    // inode-equivalence check after this step closes that gap before rename.
    // On Windows the HANDLE has dwShareMode=0 so no attacker can have
    // touched our file; the equivalence check is unnecessary there.

    std::string actual_hash = hasher.finalize();
    if (actual_hash.empty()) {
        cleanup_temp();
        return std::unexpected(UpdateError{"SHA-256 finalization failed"});
    }

    if (!iequal(actual_hash, check_resp.sha256())) {
        spdlog::error("SHA-256 mismatch: expected='{}', actual='{}'", check_resp.sha256(),
                      actual_hash);
        cleanup_temp();
        return std::unexpected(UpdateError{std::format("SHA-256 mismatch: expected '{}', got '{}'",
                                                       check_resp.sha256(), actual_hash)});
    }

    spdlog::info("SHA-256 verified: {}", actual_hash);

    // ── Step 4.5: Inode-equivalence pre-flight (POSIX, W2.3 / #806) ─────
    //
    // Confirm the inode our fd holds is the same one currently at
    // `temp_path`. If a local attacker has unlinked our temp file and
    // created a replacement at the same path (the documented attack), the
    // inodes will differ — abort before apply_update consumes the path.
    // The residual race window is from this stat() to the rename() inside
    // apply_update, which is microseconds. A Linux-only follow-up could
    // close it entirely via `linkat(AT_FDCWD, "/proc/self/fd/N", ...)`.
#ifndef _WIN32
    struct stat fd_st {};
    struct stat path_st {};
    if (::fstat(fd_guard.fd, &fd_st) < 0) {
        cleanup_temp();
        return std::unexpected(
            UpdateError{std::format("fstat on update temp fd failed: {}", std::strerror(errno))});
    }
    if (::stat(temp_path.c_str(), &path_st) < 0 || path_st.st_ino != fd_st.st_ino ||
        path_st.st_dev != fd_st.st_dev) {
        cleanup_temp();
        return std::unexpected(
            UpdateError{"update temp file inode mismatch — possible TOCTOU swap attack detected"});
    }
#endif

    // ── Step 5: Apply the update (platform-specific binary replace) ────────
    //
    // POSIX: the fd in `fd_guard` is still open here; apply_update uses
    // the path but the held fd ensures the inode stays alive (and matches
    // the hashed content per the pre-flight check above) for the duration
    // of the rename. RAII closes the fd after this function returns.
    //
    // Windows: we do the apply inline so we can rename via the held HANDLE
    // (SetFileInformationByHandle / FileRenameInfo) instead of path-based
    // fs::rename. This eliminates the residual race window — no path
    // resolution between the hash and the rename, and the rename moves the
    // inode we hashed (not whatever happens to be at `temp_path` now).

#ifdef _WIN32
    namespace fs = std::filesystem;
    auto old_path = exe_path_;
    old_path.replace_extension(".old.exe");

    std::error_code ec;
    fs::remove(old_path, ec); // best-effort: stale .old from a prior update

    // Step 5a: rename the running .exe out of the way so the destination
    // is free for the handle-rename. The .exe is locked-against-overwrite
    // by Windows but renamable, so this is safe. The .old.exe also acts
    // as the rollback target consumed by `rollback_if_needed` on next start.
    fs::rename(exe_path_, old_path, ec);
    if (ec) {
        return std::unexpected(
            UpdateError{std::format("Failed to rename running exe '{}' -> '{}': {}",
                                    exe_path_.string(), old_path.string(), ec.message())});
    }

    // Step 5b: build FILE_RENAME_INFO with FileName payload immediately
    // after the struct. FileNameLength is in bytes, NOT including any null
    // terminator. The destination path MUST be on the same volume as the
    // source — guaranteed because we placed the temp in exe_path_.parent_path().
    //
    // FileRenameInfoEx (Win10 1709+) is used instead of FileRenameInfo so
    // we can pass FILE_RENAME_FLAG_REPLACE_IF_EXISTS|POSIX_SEMANTICS:
    // even if an attacker raced us and created a stub at exe_path_ between
    // step 5a and this call, the rename atomically replaces it. POSIX
    // semantics keep any in-use handles to the original (now-orphaned)
    // file functional, which matches the rollback contract on .old.exe.
    //
    // Buffer uses std::byte with std::launder for strict-aliasing
    // correctness when the trailing array is reinterpreted as
    // FILE_RENAME_INFO. std::vector<std::byte>::data() is aligned to
    // __STDCPP_DEFAULT_NEW_ALIGNMENT__ which exceeds alignof(FILE_RENAME_INFO).
    auto target_w = exe_path_.wstring();
    const size_t fn_len_bytes = target_w.size() * sizeof(wchar_t);
    std::vector<std::byte> ri_buf(offsetof(FILE_RENAME_INFO, FileName) + fn_len_bytes);
    auto* ri = std::launder(reinterpret_cast<FILE_RENAME_INFO*>(ri_buf.data()));
    ri->Flags = FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
    ri->RootDirectory = nullptr;
    ri->FileNameLength = static_cast<DWORD>(fn_len_bytes);
    std::memcpy(ri->FileName, target_w.data(), fn_len_bytes);

    if (!SetFileInformationByHandle(h_guard.h, FileRenameInfoEx, ri,
                                    static_cast<DWORD>(ri_buf.size()))) {
        auto rename_err = GetLastError();
        // Rollback: put the running exe back. If the rollback also fails
        // the agent is in a degraded state — the binary is at old_path
        // only and the operator must manually rename or invoke
        // `yuzu-agent --rollback`. Surface that explicitly.
        std::error_code rb_ec;
        fs::rename(old_path, exe_path_, rb_ec);
        if (rb_ec) {
            spdlog::error("CRITICAL: rollback also failed: cannot rename '{}' -> '{}': {}. "
                          "Manual intervention required: rename the binary at '{}' back to '{}' "
                          "before restarting.",
                          old_path.string(), exe_path_.string(), rb_ec.message(), old_path.string(),
                          exe_path_.string());
        }
        // Drop the temp file too so we don't leave a half-applied artefact.
        // FileDispositionInfo + RAII close handles the deletion against our
        // exclusive-share hold.
        cleanup_temp();
        return std::unexpected(UpdateError{
            std::format("SetFileInformationByHandle(FileRenameInfoEx) for '{}' failed: {}",
                        exe_path_.string(), rename_err)});
    }

    spdlog::info("Update applied successfully (handle-renamed); old binary preserved at '{}'",
                 old_path.string());
    return true; // Caller should restart the process
#else
    return apply_update(temp_path);
#endif
}

#ifndef _WIN32
// apply_update is POSIX-only. On Windows the apply is performed inline in
// check_and_apply via SetFileInformationByHandle on the held HANDLE (see
// W2.3 cross-platform-debt closure). A path-based fallback on Windows
// would re-introduce the close-then-rename race window — keep it
// compile-time-absent on Windows so future refactors can't accidentally
// re-wire it.
std::expected<bool, UpdateError> Updater::apply_update(const std::filesystem::path& temp_path) {
    namespace fs = std::filesystem;
    std::error_code ec;

    // POSIX: set executable permissions on the temp file first
    fs::permissions(temp_path,
                    fs::perms::owner_exec | fs::perms::owner_read | fs::perms::owner_write, ec);
    if (ec) {
        spdlog::warn("Failed to set permissions on temp file: {}", ec.message());
        // Non-fatal: continue and let rename fail if permissions are the issue
    }

    auto old_path = exe_path_;
    old_path += ".old";

    // Remove stale .old if it exists from a prior update
    fs::remove(old_path, ec);

    // Rename current binary out of the way
    fs::rename(exe_path_, old_path, ec);
    if (ec) {
        return std::unexpected(
            UpdateError{std::format("Failed to rename current binary '{}' -> '{}': {}",
                                    exe_path_.string(), old_path.string(), ec.message())});
    }

    // Move new binary into place
    fs::rename(temp_path, exe_path_, ec);
    if (ec) {
        // Rollback: move old binary back
        std::error_code rb_ec;
        fs::rename(old_path, exe_path_, rb_ec);
        if (rb_ec) {
            spdlog::error("CRITICAL: Rollback also failed: {}", rb_ec.message());
        }
        return std::unexpected(UpdateError{std::format("Failed to place new binary at '{}': {}",
                                                       exe_path_.string(), ec.message())});
    }

    spdlog::info("Update applied successfully; old binary preserved at '{}'", old_path.string());
    return true; // Caller should restart the process
}
#endif

void Updater::cleanup_old_binary() {
    namespace fs = std::filesystem;

    auto old_path = exe_path_;
#ifdef _WIN32
    old_path.replace_extension(".old.exe");
#else
    old_path += ".old";
#endif

    std::error_code ec;
    if (fs::exists(old_path, ec)) {
        if (fs::remove(old_path, ec)) {
            spdlog::info("Cleaned up old binary: {}", old_path.string());
        } else {
            spdlog::warn("Failed to remove old binary '{}': {}", old_path.string(), ec.message());
        }
    }
}

bool Updater::rollback_if_needed() {
    namespace fs = std::filesystem;

    auto old_path = exe_path_;
#ifdef _WIN32
    old_path.replace_extension(".old.exe");
#else
    old_path += ".old";
#endif

    std::error_code ec;
    if (!fs::exists(old_path, ec)) {
        // No prior update to consider
        return false;
    }

    // Check for the verification marker written by the agent after successful
    // registration following an update
    auto marker_path = exe_path_.parent_path() / ".yuzu-update-verified";

    if (fs::exists(marker_path, ec)) {
        // The update was verified — clean up the old binary and the marker
        spdlog::info("Update verified (marker present); removing old binary");
        fs::remove(old_path, ec);
        if (ec) {
            spdlog::warn("Failed to remove old binary during verified cleanup: {}", ec.message());
        }
        fs::remove(marker_path, ec);
        return false; // No rollback needed
    }

    // The marker does not exist — the update may have failed (agent could not
    // register or crashed on startup). Roll back to the previous binary.
    spdlog::warn("Update verification marker not found — rolling back to previous binary");

    fs::rename(old_path, exe_path_, ec);
    if (ec) {
        spdlog::error("CRITICAL: Rollback failed: '{}' -> '{}': {}", old_path.string(),
                      exe_path_.string(), ec.message());
        return false;
    }

    spdlog::info("Rolled back to previous binary: {}", exe_path_.string());
    return true; // Caller should restart with the rolled-back binary
}

} // namespace yuzu::agent
