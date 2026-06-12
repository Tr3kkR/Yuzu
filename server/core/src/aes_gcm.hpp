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
#include <limits>
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

/// Guard for the int-typed EVP length API: spans larger than INT_MAX would
/// wrap negative in the `static_cast<int>` below. Decrypt inputs are bounded
/// by libpq's `int` lengths; encrypt plaintext is caller-supplied, so both
/// helpers reject oversized input explicitly.
inline bool gcm_size_ok(std::span<const std::uint8_t> s) {
    return s.size() <= static_cast<std::size_t>(std::numeric_limits<int>::max());
}

/// AES-256-GCM encrypt. `out_ciphertext` must have room for
/// `plaintext.size()` bytes (GCM is length-preserving; the tag is separate).
inline GcmResult
aes256gcm_encrypt(std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
                  std::span<const std::uint8_t> aad, std::span<const std::uint8_t> plaintext,
                  std::uint8_t* out_ciphertext, std::span<std::uint8_t, 16> out_tag) {
    if (!gcm_size_ok(aad) || !gcm_size_ok(plaintext))
        return GcmResult::error;
    EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx)
        return GcmResult::error;
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()) != 1)
        return GcmResult::error;
    // Distinct out-length variables: reusing one across the AAD and data
    // updates leaves it holding the AAD byte count when the data update is
    // skipped (legitimate empty plaintext), and `out + len` in the Final
    // call is then an out-of-bounds pointer — UB even though GCM Final
    // writes nothing (governance sec-M1).
    int aad_len = 0;
    int out_len = 0;
    int final_len = 0;
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &aad_len, aad.data(),
                                          static_cast<int>(aad.size())) != 1)
        return GcmResult::error;
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx.get(), out_ciphertext, &out_len, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1)
        return GcmResult::error;
    // GCM Final writes zero bytes (no padding), but hand it a valid pointer
    // anyway: `out_ciphertext` may be null for an empty payload.
    std::uint8_t final_scratch[EVP_MAX_BLOCK_LENGTH];
    if (EVP_EncryptFinal_ex(ctx.get(),
                            plaintext.empty() ? final_scratch : out_ciphertext + out_len,
                            &final_len) != 1)
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
    if (!gcm_size_ok(aad) || !gcm_size_ok(ciphertext))
        return GcmResult::error;
    EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx)
        return GcmResult::error;
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()) != 1)
        return GcmResult::error;
    // Distinct out-length variables — see the encrypt-side comment (sec-M1).
    int aad_len = 0;
    int out_len = 0;
    int final_len = 0;
    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &aad_len, aad.data(),
                                          static_cast<int>(aad.size())) != 1)
        return GcmResult::error;
    if (!ciphertext.empty() &&
        EVP_DecryptUpdate(ctx.get(), out_plaintext, &out_len, ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1)
        return GcmResult::error;
    // EVP_CTRL_GCM_SET_TAG takes a non-const pointer in the OpenSSL API but
    // does not modify the buffer.
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                            const_cast<std::uint8_t*>(tag.data())) != 1)
        return GcmResult::error;
    std::uint8_t final_scratch[EVP_MAX_BLOCK_LENGTH];
    if (EVP_DecryptFinal_ex(ctx.get(),
                            ciphertext.empty() ? final_scratch : out_plaintext + out_len,
                            &final_len) != 1)
        return GcmResult::auth_failed;
    return GcmResult::ok;
}

} // namespace yuzu::server::detail
