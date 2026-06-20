#pragma once

/// @file secure_buffer.hpp
/// Move-only zeroizing byte buffer for key material and recovered secrets
/// (ADR-0010 §1 "Zeroization"). The destructor runs `OPENSSL_cleanse`, which
/// resists dead-store elimination; `std::string` bounds, not guarantees,
/// zeroization, so key/secret bytes must never ride in one. This and the
/// string-only `yuzu::secure_zero` (sdk/include/yuzu/secure_zero.hpp) are the
/// only sanctioned zeroization idioms — do not add a third.
///
/// Deliberately minimal interface: no resize/reserve/append, because a
/// reallocation would orphan an uncleansed copy of the old allocation.
/// Construct at final size and fill through `data()`/`span()`.

#include <openssl/crypto.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <vector>

namespace yuzu::server {

class SecureBuffer {
public:
    SecureBuffer() = default;
    /// Zero-filled buffer of `n` bytes (fill via `data()`/`span()`).
    explicit SecureBuffer(std::size_t n) : buf_(n, 0) {}
    /// Copy `bytes` in. The CALLER still owns (and must cleanse) its source.
    explicit SecureBuffer(std::span<const std::uint8_t> bytes) : buf_(bytes.begin(), bytes.end()) {}

    ~SecureBuffer() { wipe(); }

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& o) noexcept : buf_(std::move(o.buf_)) { o.buf_.clear(); }
    SecureBuffer& operator=(SecureBuffer&& o) noexcept {
        if (this != &o) {
            wipe();
            buf_ = std::move(o.buf_);
            o.buf_.clear();
        }
        return *this;
    }

    [[nodiscard]] std::uint8_t* data() noexcept { return buf_.data(); }
    [[nodiscard]] const std::uint8_t* data() const noexcept { return buf_.data(); }
    [[nodiscard]] std::size_t size() const noexcept { return buf_.size(); }
    [[nodiscard]] bool empty() const noexcept { return buf_.empty(); }

    [[nodiscard]] std::span<std::uint8_t> span() noexcept { return {buf_.data(), buf_.size()}; }
    [[nodiscard]] std::span<const std::uint8_t> span() const noexcept {
        return {buf_.data(), buf_.size()};
    }

    /// Cleanse and release now (idempotent; the destructor calls this).
    void wipe() noexcept {
        if (!buf_.empty())
            OPENSSL_cleanse(buf_.data(), buf_.size());
        buf_.clear();
        buf_.shrink_to_fit();
    }

private:
    std::vector<std::uint8_t> buf_;
};

static_assert(!std::is_copy_constructible_v<SecureBuffer>);
static_assert(!std::is_copy_assignable_v<SecureBuffer>);
static_assert(std::is_nothrow_move_constructible_v<SecureBuffer>);
static_assert(std::is_nothrow_move_assignable_v<SecureBuffer>);

} // namespace yuzu::server
