#pragma once

/**
 * scoped_cfref.hpp -- move-only RAII owner for a CoreFoundation object.
 *
 * CoreFoundation's Create/Copy Rule hands the caller a +1 owning reference
 * from any `Create`/`Copy` function (CFStringCreate*, SCDynamicStoreCopy*,
 * CFArrayCreate*, ...) that the caller must balance with exactly one
 * `CFRelease`. `ScopedCFRef<T>` adopts that reference and calls `CFRelease`
 * on destruction, move-out, or an explicit reset() -- no double-release, no
 * leak past an early return or a thrown exception. Apple-only (guarded
 * `#if defined(__APPLE__)`): CoreFoundation.h exists nowhere else.
 *
 * Templated on the specific CF pointer typedef (`CFStringRef`,
 * `CFDictionaryRef`, ...) rather than the erased `CFTypeRef`, so a caller's
 * variable keeps its real static type (`ScopedCFRef<CFStringRef>::get()`
 * returns `CFStringRef`, no cast needed at the call site) while still
 * releasing through the common `CFRelease(CFTypeRef)` -- every CF pointer
 * type converts implicitly to `CFTypeRef` for that one call.
 *
 * Deliberately does NOT call CFRetain anywhere: this wraps an ALREADY-OWNED
 * (+1) reference, matching the Create/Copy Rule the CF APIs this is meant
 * for (nstat/SCNetwork/CoreWLAN-adjacent CF calls) always hand back. A
 * "borrow + retain" wrapper for the Get Rule (non-owned references from a
 * `CFArrayGetValueAtIndex`-style getter) is a different contract and is not
 * this type -- adding one is out of scope here (genuinely-absent primitive,
 * not a redesign of CF ownership handling).
 */

#if defined(__APPLE__)

#include <CoreFoundation/CoreFoundation.h>

#include <utility> // std::exchange

namespace yuzu::agent {

/// Owns exactly one +1 CoreFoundation reference of type `T` (a CF pointer
/// typedef, e.g. `CFStringRef`); releases it on destruction, move, or reset().
template <typename T>
class ScopedCFRef {
public:
    ScopedCFRef() noexcept = default;

    /// Adopts `ref` -- the caller must already own a +1 reference (the
    /// result of a Create/Copy call), never a borrowed (Get Rule) one.
    explicit ScopedCFRef(T ref) noexcept : ref_(ref) {}

    ScopedCFRef(const ScopedCFRef&) = delete;
    ScopedCFRef& operator=(const ScopedCFRef&) = delete;

    ScopedCFRef(ScopedCFRef&& other) noexcept : ref_(other.release()) {}
    ScopedCFRef& operator=(ScopedCFRef&& other) noexcept {
        if (this != &other)
            reset(other.release());
        return *this;
    }

    ~ScopedCFRef() { reset(); }

    /// The raw reference, or nullptr if this instance owns nothing.
    /// Ownership is retained -- do not CFRelease the result.
    [[nodiscard]] T get() const noexcept { return ref_; }

    [[nodiscard]] bool valid() const noexcept { return ref_ != nullptr; }
    explicit operator bool() const noexcept { return valid(); }

    /// Give up ownership without releasing; the caller now owns the +1
    /// reference and is responsible for its eventual CFRelease.
    [[nodiscard]] T release() noexcept { return std::exchange(ref_, nullptr); }

    /// Release the currently-owned reference (if any) and adopt `ref`
    /// instead (default nullptr: own nothing). `ref`, like the constructor
    /// argument, must already be a +1 owning reference.
    void reset(T ref = nullptr) noexcept {
        if (ref_ != nullptr)
            CFRelease(ref_);
        ref_ = ref;
    }

private:
    T ref_ = nullptr;
};

} // namespace yuzu::agent

#endif // __APPLE__
