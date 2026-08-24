#pragma once

// installed_apps_macos_enrich.hpp -- #2273 macOS `list_inventory` enrichment:
// per-app bundle identifier + signer + integrity, read NATIVELY (CFBundle +
// Security.framework's SecStaticCode API), never a subprocess. Modeled on
// certificates_plugin.cpp's read_keychain_secitem() for the
// Security/CoreFoundation linkage + ScopedCFRef discipline (the ESTABLISHED
// pattern for real CF/Security API calls in this tree); filesystem_macos_sig.hpp
// supplied the honest-status vocabulary this mirrors (valid/unsigned/unknown --
// no fabricated verdict), though that header classifies an already-captured
// `codesign` CLI result rather than calling Security.framework directly.
//
// Deliberately does NOT call SecStaticCodeCheckValidity (a deep, disk-reading
// verify) -- per #2273's own bound, this runs across every app returned by
// system_profiler (capped by the caller at kMaxEnrichApps), and a deep verify
// per app would be far too slow for a daily inventory sync. What
// SecCodeCopySigningInformation reports is therefore an INTEGRITY-at-creation
// signal only (matching filesystem_macos_sig.hpp's `valid` caveat: an ad-hoc
// or self-signed binary still reports "signed"), never a Gatekeeper/
// notarization trust verdict.
//
// ADR-0016 CRITICAL: the blob-v2 12-field row (installed_apps_inventory.hpp)
// is hashed byte-identically on agent and server. This header hands its
// caller a bundle id, publisher, and a binary signed/unsigned verdict; the
// caller (installed_apps_plugin.cpp::get_inventory_macos) fills ONLY the
// pre-existing, currently-honest-empty `publisher`/`signature_status` fields
// with it. `bundle_id` has no existing home in the frozen 12-field row and is
// deliberately NOT persisted there -- see the call site's comment and this
// PR's report for the open question this leaves for a future field (a v3
// contract bump, not a repurposed Linux-only field).

#if defined(__APPLE__)

#include <string>

#include <yuzu/agent/scoped_cfref.hpp>

#ifdef YUZU_HAVE_SECURITY_FRAMEWORK
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

namespace yuzu::installed_apps::macos_enrich {

struct EnrichResult {
    std::string bundle_id;       // CFBundleGetIdentifier -- e.g. "com.apple.Keynote"
    std::string publisher;       // the leaf signing cert's Common Name
    std::string signature_status; // "signed" | "unsigned" | "" (unknown/no
                                  // Security framework at build time -- honest-
                                  // empty, matching installed_apps_inventory.hpp's
                                  // "fields an ecosystem does not store are EMPTY,
                                  // never synthesised" contract)
};

#ifdef YUZU_HAVE_SECURITY_FRAMEWORK

namespace detail {

inline std::string cfstring_to_utf8(CFStringRef s) {
    if (!s)
        return {};
    // CFStringGetCStringPtr is a fast-path that may return null even for a
    // valid string (no guaranteed backing UTF-8 buffer); CFStringGetCString
    // always works and is what's used here, matching read_keychain_secitem's
    // sibling code in certificates_plugin.cpp for CF string extraction.
    const CFIndex len = CFStringGetLength(s);
    if (len <= 0)
        return {};
    const CFIndex max_bytes =
        CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::string out(static_cast<std::size_t>(max_bytes), '\0');
    if (!CFStringGetCString(s, out.data(), max_bytes, kCFStringEncodingUTF8))
        return {};
    out.resize(std::char_traits<char>::length(out.c_str()));
    return out;
}

} // namespace detail

// Enrich one app bundle at `app_path` (an absolute .app path, taken from a
// system_profiler "Location:" line -- see installed_apps_parsers.hpp).
// Every CoreFoundation object here is ScopedCFRef-owned (scoped_cfref.hpp) --
// read that header's reset()/same-identity contract before touching this
// function, exactly as certificates_plugin.cpp's own header comment directs.
inline EnrichResult enrich_app(const std::string& app_path) {
    EnrichResult out;

    yuzu::agent::ScopedCFRef<CFURLRef> url(CFURLCreateFromFileSystemRepresentation(
        nullptr, reinterpret_cast<const UInt8*>(app_path.c_str()),
        static_cast<CFIndex>(app_path.size()), /*isDirectory=*/true));
    if (!url)
        return out;

    // -- bundle identifier via CFBundle --
    if (auto* raw_bundle = CFBundleCreate(nullptr, url.get())) {
        yuzu::agent::ScopedCFRef<CFBundleRef> bundle(raw_bundle);
        // CFBundleGetIdentifier returns a BORROWED (Get-rule) reference owned
        // by the bundle -- never itself ScopedCFRef-wrapped, matching
        // certificates_plugin.cpp's own borrowed-vs-owned discipline.
        if (CFStringRef ident = CFBundleGetIdentifier(bundle.get()))
            out.bundle_id = detail::cfstring_to_utf8(ident);
    }

    // -- signer + integrity via SecStaticCode --
    SecStaticCodeRef raw_code = nullptr;
    const OSStatus create_status =
        SecStaticCodeCreateWithPath(url.get(), kSecCSDefaultFlags, &raw_code);
    if (create_status != errSecSuccess || !raw_code)
        return out;
    yuzu::agent::ScopedCFRef<SecStaticCodeRef> code(raw_code);

    // SecCodeCopySigningInformation's declared parameter type (SecCode.h) is
    // SecStaticCodeRef -- it takes the static code object directly, no cast
    // to SecCodeRef needed or correct here.
    CFDictionaryRef raw_info = nullptr;
    const OSStatus info_status =
        SecCodeCopySigningInformation(code.get(), kSecCSSigningInformation, &raw_info);
    if (info_status != errSecSuccess || !raw_info) {
        // errSecCSUnsigned is a POSITIVE "definitely has no signature at all"
        // -- report it honestly rather than folding it into the unknown
        // default. Any other failure (a locked/unreadable bundle, a Security
        // framework internal error, ...) stays honest-empty: this is NOT a
        // deep-verify call, so a non-errSecCSUnsigned failure here proves
        // nothing about whether the code object is actually signed.
        out.signature_status = (info_status == errSecCSUnsigned) ? "unsigned" : "";
        return out;
    }
    yuzu::agent::ScopedCFRef<CFDictionaryRef> info(raw_info);

    // CALL SUCCESS IS NOT A SIGNATURE. Measured on macOS 26 (2026-08-24):
    // SecStaticCodeCreateWithPath AND SecCodeCopySigningInformation BOTH
    // return errSecSuccess for a bundle `codesign -dv` calls "code object is
    // not signed at all" -- the dictionary simply comes back without signing
    // keys, and errSecCSUnsigned is never surfaced on this path. Reporting
    // "signed" on call success therefore labelled EVERY enriched app signed,
    // including genuinely unsigned ones -- a false positive on a
    // security-posture field (installed_apps_inventory.hpp's own wording).
    //
    // kSecCodeInfoIdentifier presence is the discriminator, verified against
    // three ground-truth cases on this host:
    //   unsigned  -> identifier ABSENT,  0 certs  => "unsigned"
    //   ad-hoc    -> identifier PRESENT, 0 certs  => "signed" (no publisher)
    //   Apple     -> identifier PRESENT, 3 certs  => "signed" + leaf CN
    // Ad-hoc/self-signed still reads "signed": integrity-at-creation only,
    // never a Gatekeeper/notarization trust verdict (the caveat this header's
    // top comment and filesystem_macos_sig.hpp both already state).
    const bool has_identifier =
        CFDictionaryGetValue(info.get(), kSecCodeInfoIdentifier) != nullptr;
    out.signature_status = has_identifier ? "signed" : "unsigned";
    if (!has_identifier)
        return out; // unsigned code has no leaf cert to read a publisher from

    if (auto* certs = static_cast<CFArrayRef>(
            CFDictionaryGetValue(info.get(), kSecCodeInfoCertificates));
        certs && CFArrayGetCount(certs) > 0) {
        // Array element is a BORROWED (Get-rule) reference owned by `certs`.
        auto leaf = static_cast<SecCertificateRef>(
            const_cast<void*>(CFArrayGetValueAtIndex(certs, 0)));
        CFStringRef raw_name = nullptr;
        if (SecCertificateCopyCommonName(leaf, &raw_name) == errSecSuccess && raw_name) {
            yuzu::agent::ScopedCFRef<CFStringRef> common_name(raw_name);
            out.publisher = detail::cfstring_to_utf8(common_name.get());
        }
    }
    return out;
}

#else // !YUZU_HAVE_SECURITY_FRAMEWORK

// A box missing the Security framework at build time compiles an honest
// no-op -- every field stays empty, matching certificates/meson.build's own
// `required: false` fallback contract.
inline EnrichResult enrich_app(const std::string& /*app_path*/) { return EnrichResult{}; }

#endif // YUZU_HAVE_SECURITY_FRAMEWORK

} // namespace yuzu::installed_apps::macos_enrich

#endif // __APPLE__
