#include <yuzu/agent/file_hash.hpp>

#include <spdlog/spdlog.h>

#ifdef _WIN32
#include <bcrypt.h>
#include <vector>
#pragma comment(lib, "bcrypt.lib")
#else
#include <cerrno>
#include <cstring>

#include <unistd.h>

#include <openssl/evp.h>
#endif

// These two functions are moved from plugin_loader.cpp's anonymous namespace
// (the #807 / W2.2 hardening): the SINGLE hardened fd/HANDLE-scoped hash
// primitive, now shared between the plugin loader and the Guardian spark state
// reader. The ONLY change from that history is the `max_bytes` bounded-read
// guard (the same one `sha256_file` carries) so untrusted, growing watched
// files cannot drive an unbounded read; plugin-loader callers pass the default
// (SIZE_MAX) and keep byte-identical behaviour.

namespace yuzu::agent {

#ifdef _WIN32
std::string sha256_from_handle(HANDLE h, std::size_t max_bytes) {
    if (h == INVALID_HANDLE_VALUE)
        return {};
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(h, zero, nullptr, FILE_BEGIN)) {
        spdlog::error("sha256_from_handle: SetFilePointerEx failed: {}", GetLastError());
        return {};
    }
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        spdlog::error("sha256_from_handle: BCryptOpenAlgorithmProvider failed: 0x{:08x}",
                      static_cast<unsigned>(status));
        return {};
    }

    DWORD obj_size = 0, data_len = 0;
    status = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_size),
                               sizeof(DWORD), &data_len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        spdlog::error("sha256_from_handle: BCryptGetProperty failed: 0x{:08x}",
                      static_cast<unsigned>(status));
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }
    std::vector<unsigned char> hash_obj(obj_size);
    status = BCryptCreateHash(alg, &hash, hash_obj.data(), static_cast<ULONG>(hash_obj.size()),
                              nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        spdlog::error("sha256_from_handle: BCryptCreateHash failed: 0x{:08x}",
                      static_cast<unsigned>(status));
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }

    constexpr DWORD kBufSize = 64 * 1024;
    std::vector<unsigned char> buf(kBufSize);
    std::uintmax_t hashed_total = 0; // bounded-read guard against max_bytes
    for (;;) {
        DWORD bytes_read = 0;
        if (!ReadFile(h, buf.data(), kBufSize, &bytes_read, nullptr)) {
            spdlog::error("sha256_from_handle: ReadFile failed: {}", GetLastError());
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            return {};
        }
        if (bytes_read == 0)
            break;
        hashed_total += static_cast<std::uintmax_t>(bytes_read);
        if (hashed_total > max_bytes) { // exceeds the read cap - refuse (oversize)
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            return {};
        }
        status = BCryptHashData(hash, buf.data(), bytes_read, 0);
        if (!BCRYPT_SUCCESS(status)) {
            spdlog::error("sha256_from_handle: BCryptHashData failed: 0x{:08x}",
                          static_cast<unsigned>(status));
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            return {};
        }
    }

    unsigned char digest[32]{};
    status = BCryptFinishHash(hash, digest, sizeof(digest), 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!BCRYPT_SUCCESS(status)) {
        spdlog::error("sha256_from_handle: BCryptFinishHash failed: 0x{:08x}",
                      static_cast<unsigned>(status));
        return {};
    }

    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(64);
    for (unsigned char b : digest) {
        hex.push_back(kHex[b >> 4]);
        hex.push_back(kHex[b & 0x0F]);
    }
    return hex;
}
#else
std::string sha256_from_fd(int fd, std::size_t max_bytes) {
    if (fd < 0)
        return {};
    if (::lseek(fd, 0, SEEK_SET) == static_cast<off_t>(-1)) {
        spdlog::error("sha256_from_fd: lseek failed: {}", std::strerror(errno));
        return {};
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        if (ctx)
            EVP_MD_CTX_free(ctx);
        return {};
    }
    constexpr size_t kBufSize = 64 * 1024;
    char buf[kBufSize];
    std::uintmax_t hashed_total = 0; // bounded-read guard against max_bytes
    for (;;) {
        ssize_t n = ::read(fd, buf, kBufSize);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            spdlog::error("sha256_from_fd: read failed: {}", std::strerror(errno));
            EVP_MD_CTX_free(ctx);
            return {};
        }
        if (n == 0)
            break;
        hashed_total += static_cast<std::uintmax_t>(n);
        if (hashed_total > max_bytes) { // exceeds the read cap - refuse (oversize)
            EVP_MD_CTX_free(ctx);
            return {};
        }
        EVP_DigestUpdate(ctx, buf, static_cast<size_t>(n));
    }
    unsigned char digest[32]{};
    unsigned int out_len = 0;
    bool ok = EVP_DigestFinal_ex(ctx, digest, &out_len) == 1 && out_len == 32;
    EVP_MD_CTX_free(ctx);
    if (!ok)
        return {};
    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(64);
    for (unsigned char b : digest) {
        hex.push_back(kHex[b >> 4]);
        hex.push_back(kHex[b & 0x0F]);
    }
    return hex;
}
#endif // _WIN32

} // namespace yuzu::agent
