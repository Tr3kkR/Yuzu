#pragma once

/// @file aes_gcm.hpp
/// One AES-256-GCM helper shared by the two ADR-0010 call sites:
/// `FileKeyProvider` (DEK wrap/unwrap under the KEK) and `SecretCodec`
/// (payload encrypt/decrypt under the DEK). One primitive throughout — the
/// ADR deliberately uses GCM for the wrap layer too rather than pulling in a
/// separate AES-KW dependency.
///
/// EVP contexts are RAII-owned (the x509_ca.cpp idiom): `EVP_CIPHER_CTX_free`
/// runs on every path. Callers own zeroization of key/plaintext buffers —
/// these helpers never copy key material anywhere it would outlive the call.

#include <openssl/evp.h>

#include <cstdint>
#include <memory>
#include <span>

namespace yuzu::server::detail {

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

enum class GcmResult {
    ok,
    auth_failed, ///< decrypt only: GCM tag verification failed (the tamper signal)
    error,       ///< EVP setup/update failure (allocation, bad lengths)
};

/// AES-256-GCM encrypt. `out_ciphertext` must have room for
/// `plaintext.size()` bytes (GCM is length-preserving; the tag is separate).
inline GcmResult
aes256gcm_encrypt(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
                  std::span<const std::uint8_t> aad, std::span<const std::uint8_t> plaintext,
                  std::uint8_t* out_ciphertext, std::span<std::uint8_t, 16> out_tag) {
    EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx)
        return GcmResult::error;
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()) != 1)
        return GcmResult::error;
    int len = 0;
    if (!aad.empty() &&
        EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
        return GcmResult::error;
    if (!plaintext.empty() && EVP_EncryptUpdate(ctx.get(), out_ciphertext, &len, plaintext.data(),
                                                static_cast<int>(plaintext.size())) != 1)
        return GcmResult::error;
    if (EVP_EncryptFinal_ex(ctx.get(), out_ciphertext + len, &len) != 1)
        return GcmResult::error;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(out_tag.size()),
                            out_tag.data()) != 1)
        return GcmResult::error;
    return GcmResult::ok;
}

/// AES-256-GCM decrypt + tag verification. `out_plaintext` must have room for
/// `ciphertext.size()` bytes. A final-step failure is reported as
/// `auth_failed` — with GCM that is the authentication verdict, not a
/// recoverable parse state (ADR-0010: the tamper signal).
inline GcmResult
aes256gcm_decrypt(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
                  std::span<const std::uint8_t> aad, std::span<const std::uint8_t> ciphertext,
                  std::span<const std::uint8_t, 16> tag, std::uint8_t* out_plaintext) {
    EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx)
        return GcmResult::error;
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()) != 1)
        return GcmResult::error;
    int len = 0;
    if (!aad.empty() &&
        EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
        return GcmResult::error;
    if (!ciphertext.empty() && EVP_DecryptUpdate(ctx.get(), out_plaintext, &len, ciphertext.data(),
                                                 static_cast<int>(ciphertext.size())) != 1)
        return GcmResult::error;
    // EVP_CTRL_GCM_SET_TAG takes a non-const pointer in the OpenSSL API but
    // does not modify the buffer.
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                            const_cast<std::uint8_t*>(tag.data())) != 1)
        return GcmResult::error;
    if (EVP_DecryptFinal_ex(ctx.get(), out_plaintext + len, &len) != 1)
        return GcmResult::auth_failed;
    return GcmResult::ok;
}

} // namespace yuzu::server::detail
