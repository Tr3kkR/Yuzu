/**
 * updater.cpp — Agent-side OTA update: check, download, verify, self-replace
 *
 * Implements the Updater class declared in <yuzu/agent/updater.hpp>.
 * Uses platform-specific crypto for SHA-256 (BCrypt on Windows, OpenSSL EVP
 * on POSIX) and platform-specific filesystem operations for atomic binary
 * replacement with rollback support.
 */

#include <yuzu/agent/updater.hpp>
#include <yuzu/plugin.h>  // yuzu_create_temp_file

// Generated protobuf/gRPC headers (flat output from YuzuProto.cmake)
#include "agent.grpc.pb.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <format>
#include <string>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
#else
#  include <openssl/evp.h>
#  ifdef __APPLE__
#    include <mach-o/dyld.h>  // _NSGetExecutablePath
#  endif
#endif

namespace yuzu::agent {

namespace {

namespace pb = ::yuzu::agent::v1;

// ── SHA-256 incremental hasher ─────────────────────────────────────────────

class Sha256Hasher {
public:
    Sha256Hasher() {
#ifdef _WIN32
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &alg_, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status)) {
            spdlog::error("BCryptOpenAlgorithmProvider failed: 0x{:08x}", static_cast<unsigned>(status));
            valid_ = false;
            return;
        }

        DWORD obj_size = 0;
        DWORD data_len = 0;
        status = BCryptGetProperty(alg_, BCRYPT_OBJECT_LENGTH,
                                   reinterpret_cast<PUCHAR>(&obj_size),
                                   sizeof(DWORD), &data_len, 0);
        if (!BCRYPT_SUCCESS(status)) {
            spdlog::error("BCryptGetProperty failed: 0x{:08x}", static_cast<unsigned>(status));
            BCryptCloseAlgorithmProvider(alg_, 0);
            valid_ = false;
            return;
        }

        hash_obj_.resize(obj_size);
        status = BCryptCreateHash(alg_, &hash_,
                                  hash_obj_.data(), static_cast<ULONG>(hash_obj_.size()),
                                  nullptr, 0, 0);
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
            if (ctx_) { EVP_MD_CTX_free(ctx_); ctx_ = nullptr; }
            valid_ = false;
            return;
        }
        valid_ = true;
#endif
    }

    ~Sha256Hasher() {
#ifdef _WIN32
        if (hash_)  BCryptDestroyHash(hash_);
        if (alg_)   BCryptCloseAlgorithmProvider(alg_, 0);
#else
        if (ctx_)    EVP_MD_CTX_free(ctx_);
#endif
    }

    Sha256Hasher(const Sha256Hasher&) = delete;
    Sha256Hasher& operator=(const Sha256Hasher&) = delete;

    [[nodiscard]] bool is_valid() const noexcept { return valid_; }

    bool update(const void* data, size_t len) {
        if (!valid_) return false;
#ifdef _WIN32
        NTSTATUS status = BCryptHashData(
            hash_,
            static_cast<PUCHAR>(const_cast<void*>(data)),
            static_cast<ULONG>(len), 0);
        return BCRYPT_SUCCESS(status);
#else
        return EVP_DigestUpdate(ctx_, data, len) == 1;
#endif
    }

    /// Finalize and return lowercase hex-encoded SHA-256 digest.
    [[nodiscard]] std::string finalize() {
        if (!valid_) return {};

        constexpr size_t kDigestLen = 32;  // SHA-256 = 256 bits = 32 bytes
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
    BCRYPT_ALG_HANDLE  alg_{nullptr};
    BCRYPT_HASH_HANDLE hash_{nullptr};
    std::vector<unsigned char> hash_obj_;
#else
    EVP_MD_CTX* ctx_{nullptr};
#endif
};

/// Case-insensitive string equality.
bool iequal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    return std::ranges::equal(a, b, [](char lhs, char rhs) {
        return std::tolower(static_cast<unsigned char>(lhs)) ==
               std::tolower(static_cast<unsigned char>(rhs));
    });
}

}  // anonymous namespace

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

Updater::Updater(UpdateConfig config, std::string agent_id,
                 std::string current_version, std::string os,
                 std::string arch, std::filesystem::path exe_path)
    : config_{std::move(config)}
    , agent_id_{std::move(agent_id)}
    , current_version_{std::move(current_version)}
    , os_{std::move(os)}
    , arch_{std::move(arch)}
    , exe_path_{std::move(exe_path)}
{}

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
            std::format("CheckForUpdate RPC failed: {} (code {})",
                        check_status.error_message(),
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

    spdlog::info("Update available: {} -> {} ({} bytes, mandatory={})",
                 current_version_, check_resp.latest_version(),
                 check_resp.file_size(), check_resp.mandatory());

    if (stop_requested_.load(std::memory_order_acquire)) {
        return false;
    }

    // ── Step 2: Create temp file for download ──────────────────────────────

    char path_buf[512]{};
    int rc = yuzu_create_temp_file("yuzu-update-", ".tmp", nullptr, path_buf, sizeof(path_buf));
    if (rc != 0) {
        return std::unexpected(UpdateError{"Failed to create temporary file for update download"});
    }
    std::filesystem::path temp_path{path_buf};

    // ── Step 3: Download the update binary ─────────────────────────────────

    pb::DownloadUpdateRequest dl_req;
    dl_req.set_agent_id(agent_id_);
    dl_req.set_version(check_resp.latest_version());
    auto* dl_platform = dl_req.mutable_platform();
    dl_platform->set_os(os_);
    dl_platform->set_arch(arch_);

    grpc::ClientContext dl_ctx;
    auto reader = stub->DownloadUpdate(&dl_ctx, dl_req);

    std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        std::error_code ec;
        std::filesystem::remove(temp_path, ec);
        return std::unexpected(UpdateError{
            std::format("Failed to open temp file '{}' for writing", temp_path.string())});
    }

    Sha256Hasher hasher;
    if (!hasher.is_valid()) {
        out.close();
        std::error_code ec;
        std::filesystem::remove(temp_path, ec);
        return std::unexpected(UpdateError{"Failed to initialize SHA-256 hasher"});
    }

    int64_t bytes_downloaded = 0;
    pb::DownloadUpdateChunk chunk;

    while (reader->Read(&chunk)) {
        if (stop_requested_.load(std::memory_order_acquire)) {
            out.close();
            std::error_code ec;
            std::filesystem::remove(temp_path, ec);
            return false;
        }

        const auto& data = chunk.data();
        out.write(data.data(), static_cast<std::streamsize>(data.size()));
        if (!out) {
            out.close();
            std::error_code ec;
            std::filesystem::remove(temp_path, ec);
            return std::unexpected(UpdateError{"Write to temp file failed during download"});
        }

        if (!hasher.update(data.data(), data.size())) {
            out.close();
            std::error_code ec;
            std::filesystem::remove(temp_path, ec);
            return std::unexpected(UpdateError{"SHA-256 hash update failed during download"});
        }

        bytes_downloaded += static_cast<int64_t>(data.size());
    }

    grpc::Status dl_status = reader->Finish();
    out.close();

    if (!dl_status.ok()) {
        std::error_code ec;
        std::filesystem::remove(temp_path, ec);
        return std::unexpected(UpdateError{
            std::format("DownloadUpdate RPC failed: {} (code {})",
                        dl_status.error_message(),
                        static_cast<int>(dl_status.error_code()))});
    }

    spdlog::info("Downloaded {} bytes for update {}", bytes_downloaded, check_resp.latest_version());

    // ── Step 4: Verify SHA-256 ─────────────────────────────────────────────

    std::string actual_hash = hasher.finalize();
    if (actual_hash.empty()) {
        std::error_code ec;
        std::filesystem::remove(temp_path, ec);
        return std::unexpected(UpdateError{"SHA-256 finalization failed"});
    }

    if (!iequal(actual_hash, check_resp.sha256())) {
        spdlog::error("SHA-256 mismatch: expected='{}', actual='{}'",
                      check_resp.sha256(), actual_hash);
        std::error_code ec;
        std::filesystem::remove(temp_path, ec);
        return std::unexpected(UpdateError{
            std::format("SHA-256 mismatch: expected '{}', got '{}'",
                        check_resp.sha256(), actual_hash)});
    }

    spdlog::info("SHA-256 verified: {}", actual_hash);

    // ── Step 5: Apply the update (platform-specific binary replace) ────────

    return apply_update(temp_path);
}

std::expected<bool, UpdateError>
Updater::apply_update(const std::filesystem::path& temp_path) {
    namespace fs = std::filesystem;
    std::error_code ec;

#ifdef _WIN32
    // On Windows the running .exe can be renamed but not overwritten.
    auto old_path = exe_path_;
    old_path.replace_extension(".old.exe");

    // Remove stale .old if it exists from a prior update
    fs::remove(old_path, ec);

    // Rename the running exe out of the way
    fs::rename(exe_path_, old_path, ec);
    if (ec) {
        return std::unexpected(UpdateError{
            std::format("Failed to rename running exe '{}' -> '{}': {}",
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
        return std::unexpected(UpdateError{
            std::format("Failed to place new binary at '{}': {}",
                        exe_path_.string(), ec.message())});
    }
#else
    // POSIX: set executable permissions on the temp file first
    fs::permissions(temp_path,
                    fs::perms::owner_exec | fs::perms::owner_read | fs::perms::owner_write,
                    ec);
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
        return std::unexpected(UpdateError{
            std::format("Failed to rename current binary '{}' -> '{}': {}",
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
        return std::unexpected(UpdateError{
            std::format("Failed to place new binary at '{}': {}",
                        exe_path_.string(), ec.message())});
    }
#endif

    spdlog::info("Update applied successfully; old binary preserved at '{}'",
                 old_path.string());
    return true;  // Caller should restart the process
}

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
            spdlog::warn("Failed to remove old binary '{}': {}",
                         old_path.string(), ec.message());
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
            spdlog::warn("Failed to remove old binary during verified cleanup: {}",
                         ec.message());
        }
        fs::remove(marker_path, ec);
        return false;  // No rollback needed
    }

    // The marker does not exist — the update may have failed (agent could not
    // register or crashed on startup). Roll back to the previous binary.
    spdlog::warn("Update verification marker not found — rolling back to previous binary");

    fs::rename(old_path, exe_path_, ec);
    if (ec) {
        spdlog::error("CRITICAL: Rollback failed: '{}' -> '{}': {}",
                       old_path.string(), exe_path_.string(), ec.message());
        return false;
    }

    spdlog::info("Rolled back to previous binary: {}", exe_path_.string());
    return true;  // Caller should restart with the rolled-back binary
}

}  // namespace yuzu::agent
