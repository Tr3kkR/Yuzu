#include <yuzu/agent/cert_store.hpp>

#include <spdlog/spdlog.h>

#include <string>
#include <vector>

#ifdef _WIN32
// clang-format off
#include <winsock2.h>  // must precede windows.h
#include <windows.h>
// clang-format on
#include <ncrypt.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

namespace yuzu::agent {

namespace {

// Convert a hex-encoded thumbprint string to raw bytes.
// Accepts "AB12CD..." or "AB:12:CD:..." (with or without colons/spaces).
std::vector<unsigned char> parse_thumbprint(const std::string& hex) {
    std::vector<unsigned char> bytes;
    bytes.reserve(20); // SHA-1 = 20 bytes
    for (size_t i = 0; i < hex.size();) {
        char c = hex[i];
        if (c == ':' || c == ' ') {
            ++i;
            continue;
        }
        if (i + 1 >= hex.size())
            break;
        auto hi = hex[i], lo = hex[i + 1];
        auto nibble = [](char ch) -> unsigned char {
            if (ch >= '0' && ch <= '9')
                return static_cast<unsigned char>(ch - '0');
            if (ch >= 'a' && ch <= 'f')
                return static_cast<unsigned char>(ch - 'a' + 10);
            if (ch >= 'A' && ch <= 'F')
                return static_cast<unsigned char>(ch - 'A' + 10);
            return 0;
        };
        bytes.push_back(static_cast<unsigned char>((nibble(hi) << 4) | nibble(lo)));
        i += 2;
    }
    return bytes;
}

// PEM-encode a DER blob with the given label (e.g. "CERTIFICATE", "RSA PRIVATE KEY").
std::string pem_encode(const std::string& label, const unsigned char* data, size_t len) {
    // Base64 encode
    DWORD b64_len = 0;
    CryptBinaryToStringA(data, static_cast<DWORD>(len), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                         nullptr, &b64_len);
    std::string b64(b64_len, '\0');
    CryptBinaryToStringA(data, static_cast<DWORD>(len), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                         b64.data(), &b64_len);
    b64.resize(b64_len);

    // Wrap at 64 characters per line
    std::string pem = "-----BEGIN " + label + "-----\n";
    for (size_t i = 0; i < b64.size(); i += 64) {
        pem += b64.substr(i, 64) + "\n";
    }
    pem += "-----END " + label + "-----\n";
    return pem;
}

} // anonymous namespace

CertStoreResult read_cert_from_store(const std::string& store_name, const std::string& subject,
                                     const std::string& thumbprint) {
    CertStoreResult result;

    // Open the Local Machine certificate store
    auto store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                               CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
                               store_name.c_str());

    if (!store) {
        // Fall back to Current User store
        store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                              CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
                              store_name.c_str());
    }

    if (!store) {
        result.error = "Failed to open certificate store '" + store_name + "' (error " +
                       std::to_string(GetLastError()) + ")";
        return result;
    }

    PCCERT_CONTEXT cert_ctx = nullptr;

    if (!thumbprint.empty()) {
        // Search by SHA-1 thumbprint
        auto hash_bytes = parse_thumbprint(thumbprint);
        CRYPT_HASH_BLOB hash_blob;
        hash_blob.cbData = static_cast<DWORD>(hash_bytes.size());
        hash_blob.pbData = hash_bytes.data();

        cert_ctx = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                              CERT_FIND_HASH, &hash_blob, nullptr);

        if (!cert_ctx) {
            result.error = "No certificate found with thumbprint '" + thumbprint + "'";
            CertCloseStore(store, 0);
            return result;
        }
        spdlog::info("Found certificate by thumbprint: {}", thumbprint);

    } else if (!subject.empty()) {
        // Search by subject CN substring
        cert_ctx = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                              CERT_FIND_SUBJECT_STR_A, subject.c_str(), nullptr);

        if (!cert_ctx) {
            result.error = "No certificate found with subject matching '" + subject + "'";
            CertCloseStore(store, 0);
            return result;
        }

        // Log the matched subject for diagnostics
        char subject_name[256] = {};
        CertGetNameStringA(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject_name,
                           sizeof(subject_name));
        spdlog::info("Found certificate by subject: {}", subject_name);

    } else {
        result.error = "Either --cert-subject or --cert-thumbprint is required with --cert-store";
        CertCloseStore(store, 0);
        return result;
    }

    // ── Extract the certificate chain as PEM ─────────────────────────────────

    // Build the certificate chain to include intermediate CAs
    CERT_CHAIN_PARA chain_para = {};
    chain_para.cbSize = sizeof(chain_para);
    PCCERT_CHAIN_CONTEXT chain_ctx = nullptr;

    BOOL chain_ok = CertGetCertificateChain(nullptr, // default chain engine
                                            cert_ctx,
                                            nullptr, // current time
                                            store,   // additional store to search
                                            &chain_para,
                                            0,       // flags
                                            nullptr, // reserved
                                            &chain_ctx);

    std::string cert_pem;
    if (chain_ok && chain_ctx && chain_ctx->cChain > 0) {
        // Walk the first simple chain — leaf first, then intermediates
        auto* simple_chain = chain_ctx->rgpChain[0];
        for (DWORD i = 0; i < simple_chain->cElement; ++i) {
            auto* elem = simple_chain->rgpElement[i]->pCertContext;
            cert_pem += pem_encode("CERTIFICATE", elem->pbCertEncoded, elem->cbCertEncoded);
        }
    } else {
        // Fall back to just the leaf certificate
        cert_pem = pem_encode("CERTIFICATE", cert_ctx->pbCertEncoded, cert_ctx->cbCertEncoded);
    }

    if (chain_ctx)
        CertFreeCertificateChain(chain_ctx);

    result.pem_cert_chain = std::move(cert_pem);

    // ── Extract the private key ──────────────────────────────────────────────

    DWORD key_spec = 0;
    BOOL caller_free = FALSE;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key_handle = 0;

    BOOL key_ok = CryptAcquireCertificatePrivateKey(
        cert_ctx, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, nullptr,
        &key_handle, &key_spec, &caller_free);

    if (!key_ok || key_handle == 0) {
        // Try legacy CSP path
        key_ok = CryptAcquireCertificatePrivateKey(cert_ctx, CRYPT_ACQUIRE_SILENT_FLAG, nullptr,
                                                   &key_handle, &key_spec, &caller_free);
    }

    if (!key_ok || key_handle == 0) {
        result.error = "Certificate found but private key is not accessible "
                       "(error " +
                       std::to_string(GetLastError()) +
                       "). "
                       "Ensure the key is marked as exportable and the agent runs "
                       "with sufficient privileges (Local System or admin).";
        CertFreeCertificateContext(cert_ctx);
        CertCloseStore(store, 0);
        return result;
    }

    // Export the private key via NCrypt (CNG) or legacy CAPI
    if (key_spec == CERT_NCRYPT_KEY_SPEC) {
        // CNG key — export as PKCS#8 blob, then PEM-encode
        DWORD blob_len = 0;
        SECURITY_STATUS ss =
            NCryptExportKey(key_handle, 0,
                            BCRYPT_RSAFULLPRIVATE_BLOB, // or NCRYPT_PKCS8_PRIVATE_KEY_BLOB
                            nullptr, nullptr, 0, &blob_len, 0);

        // Try PKCS#8 first (more portable)
        ss = NCryptExportKey(key_handle, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, nullptr, nullptr, 0,
                             &blob_len, 0);

        if (ss == ERROR_SUCCESS && blob_len > 0) {
            std::vector<unsigned char> blob(blob_len);
            ss = NCryptExportKey(key_handle, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, nullptr, blob.data(),
                                 blob_len, &blob_len, 0);

            if (ss == ERROR_SUCCESS) {
                result.pem_private_key = pem_encode("PRIVATE KEY", blob.data(), blob_len);
            } else {
                result.error = "NCryptExportKey (PKCS8) failed: " + std::to_string(ss) +
                               ". The private key may not be marked as exportable.";
            }
            // Zero private key material from intermediate buffer
            SecureZeroMemory(blob.data(), blob.size());
        } else {
            result.error = "NCryptExportKey failed: " + std::to_string(ss) +
                           ". The private key may not be marked as exportable.";
        }

        if (caller_free)
            NCryptFreeObject(key_handle);
    } else {
        // Legacy CAPI key — export as PRIVATEKEYBLOB, convert to PKCS#8
        HCRYPTKEY hkey = 0;
        if (CryptGetUserKey(key_handle, key_spec, &hkey)) {
            DWORD blob_len = 0;
            CryptExportKey(hkey, 0, PRIVATEKEYBLOB, 0, nullptr, &blob_len);

            if (blob_len > 0) {
                std::vector<unsigned char> blob(blob_len);
                if (CryptExportKey(hkey, 0, PRIVATEKEYBLOB, 0, blob.data(), &blob_len)) {
                    // Convert CAPI PRIVATEKEYBLOB to PKCS#8 DER
                    DWORD der_len = 0;
                    if (CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                            PKCS_RSA_PRIVATE_KEY, blob.data(), 0, nullptr, nullptr,
                                            &der_len) &&
                        der_len > 0) {
                        std::vector<unsigned char> der(der_len);
                        if (CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                PKCS_RSA_PRIVATE_KEY, blob.data(), 0, nullptr,
                                                der.data(), &der_len)) {
                            result.pem_private_key =
                                pem_encode("RSA PRIVATE KEY", der.data(), der_len);
                        }
                    }

                    if (result.pem_private_key.empty()) {
                        // Fall back: encode the raw CAPI blob as RSA PRIVATE KEY
                        // (may not be standard PEM, but gRPC can sometimes handle it)
                        result.error = "Failed to convert CAPI private key to PEM format.";
                    }
                } else {
                    result.error = "CryptExportKey failed. The key may not be exportable.";
                }
                // Zero private key material from intermediate buffer
                SecureZeroMemory(blob.data(), blob.size());
            }
            CryptDestroyKey(hkey);
        } else {
            result.error = "CryptGetUserKey failed (error " + std::to_string(GetLastError()) + ")";
        }

        if (caller_free)
            CryptReleaseContext(key_handle, 0);
    }

    // Cleanup
    CertFreeCertificateContext(cert_ctx);
    CertCloseStore(store, 0);

    return result;
}

} // namespace yuzu::agent

#elif defined(__APPLE__) // macOS — Security framework keychain identity

#ifdef YUZU_HAVE_SECURITY

// clang-format off
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
// clang-format on

#include <openssl/evp.h>

#include <algorithm>
#include <array>

namespace yuzu::agent {

namespace {

// ── RAII for Core Foundation / Security reference types ─────────────────────
// Every Sec*Ref / CF*Ref handed back by a "Copy" or "Create" function is +1
// retained and must be CFRelease()'d exactly once. One generic owner covers
// all of them — SecKeychainRef, SecIdentityRef, SecCertificateRef, SecKeyRef,
// SecTrustRef, SecPolicyRef, CFArrayRef, CFDictionaryRef, CFDataRef,
// CFStringRef... are all toll-free-bridged CFTypeRef under the hood, so
// CFRelease() is always the right call regardless of which one T is.
template <typename CFT>
class CFOwned {
public:
    CFOwned() = default;
    explicit CFOwned(CFT ref) : ref_(ref) {}
    CFOwned(const CFOwned&) = delete;
    CFOwned& operator=(const CFOwned&) = delete;
    CFOwned(CFOwned&& other) noexcept : ref_(other.ref_) { other.ref_ = nullptr; }
    CFOwned& operator=(CFOwned&& other) noexcept {
        if (this != &other) {
            reset();
            ref_ = other.ref_;
            other.ref_ = nullptr;
        }
        return *this;
    }
    ~CFOwned() { reset(); }

    // Out-param slot for a Copy/Create-style call whose signature takes a T*,
    // e.g. `SecIdentityCopyCertificate(id, cert.out())`.
    CFT* out() {
        reset();
        return &ref_;
    }
    CFT get() const { return ref_; }
    explicit operator bool() const { return ref_ != nullptr; }

    void reset(CFT ref = nullptr) {
        if (ref_ != nullptr)
            CFRelease(ref_);
        ref_ = ref;
    }

private:
    CFT ref_ = nullptr;
};

std::string cfstring_to_utf8(CFStringRef s) {
    if (s == nullptr)
        return {};
    if (const char* fast = CFStringGetCStringPtr(s, kCFStringEncodingUTF8))
        return std::string(fast);
    const CFIndex len = CFStringGetLength(s);
    const CFIndex max_bytes = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::vector<char> buf(static_cast<size_t>(max_bytes), '\0');
    if (CFStringGetCString(s, buf.data(), max_bytes, kCFStringEncodingUTF8))
        return std::string(buf.data());
    return {};
}

std::string cfdata_to_std(CFDataRef d) {
    if (d == nullptr)
        return {};
    const UInt8* p = CFDataGetBytePtr(d);
    const CFIndex n = CFDataGetLength(d);
    if (p == nullptr || n <= 0)
        return {};
    return std::string(reinterpret_cast<const char*>(p), static_cast<size_t>(n));
}

// Best-effort in-place wipe of a CFDataRef's bytes before it is released.
// CFRelease() only frees the backing store — it makes no secure-erase
// guarantee — so this is the only way to keep exported PRIVATE KEY bytes
// from lingering in a freed heap allocation a later memory disclosure could
// read. Only ever call this on a freshly Copy/Create'd CFData this function
// exclusively owns (e.g. straight out of SecItemExport), never on a CFData
// obtained any other way — writing through an immutable CFDataRef's byte
// pointer is safe exactly because nothing else holds or has read that
// backing store yet. `volatile` defeats the dead-store elimination a plain
// memset with no later read would otherwise be eligible for, the same
// concern that makes plain memset() unsuitable for this on any platform and
// mirrors the intent of Windows' SecureZeroMemory() used on the equivalent
// CAPI/CNG blobs above.
void secure_wipe_cfdata(CFDataRef data) {
    if (data == nullptr)
        return;
    const CFIndex len = CFDataGetLength(data);
    if (len <= 0)
        return;
    auto* bytes = const_cast<UInt8*>(CFDataGetBytePtr(data));
    if (bytes == nullptr)
        return;
    volatile UInt8* p = bytes;
    for (CFIndex i = 0; i < len; ++i)
        p[i] = 0;
}

// Human-readable OSStatus where the OS has text for it, else the bare code.
std::string describe(OSStatus status) {
    CFOwned<CFStringRef> msg(SecCopyErrorMessageString(status, nullptr));
    if (msg) {
        auto s = cfstring_to_utf8(msg.get());
        if (!s.empty())
            return s;
    }
    return "OSStatus " + std::to_string(static_cast<int>(status));
}

// Hex-decode "AB12CD..." / "AB:12:CD:..." (colon/space tolerant) to raw
// bytes — byte-identical contract to the Windows parse_thumbprint() above, so
// --cert-thumbprint means exactly the same thing on every platform.
std::vector<unsigned char> parse_thumbprint(const std::string& hex) {
    std::vector<unsigned char> bytes;
    bytes.reserve(20); // SHA-1 = 20 bytes
    for (size_t i = 0; i < hex.size();) {
        char c = hex[i];
        if (c == ':' || c == ' ') {
            ++i;
            continue;
        }
        if (i + 1 >= hex.size())
            break;
        auto hi = hex[i], lo = hex[i + 1];
        auto nibble = [](char ch) -> unsigned char {
            if (ch >= '0' && ch <= '9')
                return static_cast<unsigned char>(ch - '0');
            if (ch >= 'a' && ch <= 'f')
                return static_cast<unsigned char>(ch - 'a' + 10);
            if (ch >= 'A' && ch <= 'F')
                return static_cast<unsigned char>(ch - 'A' + 10);
            return 0;
        };
        bytes.push_back(static_cast<unsigned char>((nibble(hi) << 4) | nibble(lo)));
        i += 2;
    }
    return bytes;
}

// RAII owner for EVP_MD_CTX, mirroring the guard in file_hash.cpp's OpenSSL
// (non-Windows) path — a bad_alloc from a string/vector allocation between a
// successful EVP_MD_CTX_new() and its paired free must not leak the context.
struct EvpMdCtxGuard {
    EVP_MD_CTX* ctx = nullptr;
    ~EvpMdCtxGuard() {
        if (ctx)
            EVP_MD_CTX_free(ctx);
    }
    EvpMdCtxGuard(const EvpMdCtxGuard&) = delete;
    EvpMdCtxGuard& operator=(const EvpMdCtxGuard&) = delete;
    EvpMdCtxGuard() = default;
};

// SHA-1 of a raw DER blob — what a "certificate thumbprint" actually is (what
// Windows Certificate Manager and `openssl x509 -fingerprint -sha1` both show
// as the cert's thumbprint/fingerprint). Returns false on any OpenSSL failure
// so a hash the caller couldn't compute is never mistaken for a comparable
// digest — an honest skip, not a wrong-but-plausible zero.
bool sha1_digest(const unsigned char* data, size_t len, std::array<unsigned char, 20>& out) {
    if (data == nullptr)
        return false;
    EvpMdCtxGuard guard;
    guard.ctx = EVP_MD_CTX_new();
    if (!guard.ctx)
        return false;
    if (EVP_DigestInit_ex(guard.ctx, EVP_sha1(), nullptr) != 1)
        return false;
    if (EVP_DigestUpdate(guard.ctx, data, len) != 1)
        return false;
    unsigned int out_len = 0;
    return EVP_DigestFinal_ex(guard.ctx, out.data(), &out_len) == 1 && out_len == out.size();
}

// PEM-armor a certificate via SecItemExport — the format+flag combination
// does the base64/header/footer work for us, unlike the Windows CryptoAPI
// path, which has to build the PEM text by hand.
bool export_cert_pem(SecCertificateRef cert, std::string& out_pem, std::string& err) {
    CFOwned<CFDataRef> exported;
    OSStatus st =
        SecItemExport(cert, kSecFormatX509Cert, kSecItemPemArmour, nullptr, exported.out());
    if (st != errSecSuccess || !exported) {
        err = "SecItemExport(certificate) failed: " + describe(st);
        return false;
    }
    out_pem = cfdata_to_std(exported.get());
    if (out_pem.empty()) {
        // errSecSuccess with empty/unreadable output is not a success — an
        // empty pem_cert_chain would otherwise slip past
        // CertStoreResult::ok() (error.empty()) and hand gRPC a credential
        // with no certificate.
        err = "SecItemExport(certificate) returned empty data";
        return false;
    }
    return true;
}

// PEM-armor a private key. kSecFormatUnknown lets Security pick the key's
// natural format (PKCS#1 RSAPrivateKey for RSA, SEC1 ECPrivateKey for EC);
// passing no keyParams/passphrase is what makes this produce an UNENCRYPTED
// PEM for a plain exportable key instead of asking for one — a key whose ACL
// mandates a passphrase for export fails this call instead (honest error); it
// never blocks on a prompt.
bool export_key_pem(SecKeyRef key, std::string& out_pem, std::string& err) {
    CFOwned<CFDataRef> exported;
    OSStatus st = SecItemExport(key, kSecFormatUnknown, kSecItemPemArmour, nullptr, exported.out());
    if (st != errSecSuccess || !exported) {
        err = "SecItemExport(private key) failed: " + describe(st) +
              ". The key may not be marked exportable, or its access control requires a "
              "passphrase this non-interactive path cannot supply.";
        return false;
    }
    out_pem = cfdata_to_std(exported.get());
    // Scrub the Security-owned export buffer before CFOwned's destructor
    // releases it below — cfdata_to_std() has already made our own copy in
    // out_pem, so nothing further needs these bytes.
    secure_wipe_cfdata(exported.get());
    if (out_pem.empty()) {
        // errSecSuccess with empty/unreadable output is not a success — an
        // empty pem_private_key would otherwise slip past
        // CertStoreResult::ok() (error.empty()) and hand gRPC a credential
        // with no private key.
        err = "SecItemExport(private key) returned empty data";
        return false;
    }
    return true;
}

// Exactly one identity whose leaf subject CONTAINS `needle` — the same
// substring semantics as Windows' CERT_FIND_SUBJECT_STR_A. kSecMatchLimitOne
// means SecItemCopyMatching hands back the bare item, not a CFArray, and the
// caller receives its own +1 reference directly (no extra CFRetain needed).
bool find_identity_by_subject(CFArrayRef search_list, const std::string& needle,
                              CFOwned<SecIdentityRef>& out_identity, std::string& err) {
    CFOwned<CFStringRef> needle_cf(
        CFStringCreateWithCString(kCFAllocatorDefault, needle.c_str(), kCFStringEncodingUTF8));
    if (!needle_cf) {
        err = "Subject '" + needle + "' is not valid UTF-8";
        return false;
    }

    CFOwned<CFMutableDictionaryRef> query(CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    if (!query) {
        err = "Failed to allocate a Core Foundation dictionary for the keychain query";
        return false;
    }
    CFDictionarySetValue(query.get(), kSecClass, kSecClassIdentity);
    CFDictionarySetValue(query.get(), kSecMatchSearchList, search_list);
    CFDictionarySetValue(query.get(), kSecMatchLimit, kSecMatchLimitOne);
    CFDictionarySetValue(query.get(), kSecReturnRef, kCFBooleanTrue);
    // Never let a locked keychain or a protected-ACL item summon the
    // SecurityAgent password prompt — fail the lookup instead. Load-bearing
    // for the "no interactive prompt" guarantee on the search step.
    CFDictionarySetValue(query.get(), kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
    CFDictionarySetValue(query.get(), kSecMatchSubjectContains, needle_cf.get());

    CFTypeRef raw = nullptr;
    OSStatus st = SecItemCopyMatching(query.get(), &raw);
    if (st != errSecSuccess || raw == nullptr) {
        err = "No certificate found in the login keychain with subject matching '" + needle +
              "' (" + describe(st) + ")";
        return false;
    }
    out_identity.reset(static_cast<SecIdentityRef>(const_cast<void*>(raw)));
    spdlog::info("Found certificate in login keychain by subject: {}", needle);
    return true;
}

// The identity whose LEAF certificate's SHA-1 fingerprint (the hash of the
// WHOLE DER-encoded certificate — what an operator would copy as a
// "thumbprint") equals `thumbprint_hex`. Keychain's SecItem query language
// has no predicate for this: its one built-in cert-hash attribute,
// kSecAttrPublicKeyHash, hashes the SUBJECT PUBLIC KEY, not the certificate —
// wiring that up here would silently match the wrong certificate (or none),
// exactly the kind of quiet correctness bug this package exists to avoid. So:
// enumerate every identity in the login keychain and compare each leaf's real
// SHA-1(DER) ourselves — what CertFindCertificateInStore(CERT_FIND_HASH) does
// internally on the Windows side of this same file.
bool find_identity_by_thumbprint(CFArrayRef search_list, const std::string& thumbprint_hex,
                                 CFOwned<SecIdentityRef>& out_identity, std::string& err) {
    const auto wanted = parse_thumbprint(thumbprint_hex);
    if (wanted.size() != 20) {
        err = "Certificate thumbprint '" + thumbprint_hex + "' is not a 20-byte SHA-1 hash";
        return false;
    }

    CFOwned<CFMutableDictionaryRef> query(CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
    if (!query) {
        err = "Failed to allocate a Core Foundation dictionary for the keychain query";
        return false;
    }
    CFDictionarySetValue(query.get(), kSecClass, kSecClassIdentity);
    CFDictionarySetValue(query.get(), kSecMatchSearchList, search_list);
    CFDictionarySetValue(query.get(), kSecMatchLimit, kSecMatchLimitAll);
    CFDictionarySetValue(query.get(), kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query.get(), kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);

    CFTypeRef raw = nullptr;
    OSStatus st = SecItemCopyMatching(query.get(), &raw);
    if (st != errSecSuccess || raw == nullptr) {
        err = "No certificates found in the login keychain to search by thumbprint (" +
              describe(st) + ")";
        return false;
    }
    // kSecMatchLimitAll returns a CFArray whose elements the ARRAY retains —
    // any element we want to keep past this array's lifetime needs its own
    // explicit CFRetain (see below), unlike the single-item kSecMatchLimitOne
    // case in find_identity_by_subject() above.
    CFOwned<CFArrayRef> candidates(static_cast<CFArrayRef>(const_cast<void*>(raw)));

    const CFIndex n = CFArrayGetCount(candidates.get());
    for (CFIndex i = 0; i < n; ++i) {
        auto identity = static_cast<SecIdentityRef>(
            const_cast<void*>(CFArrayGetValueAtIndex(candidates.get(), i)));
        CFOwned<SecCertificateRef> cert;
        if (SecIdentityCopyCertificate(identity, cert.out()) != errSecSuccess || !cert)
            continue;
        CFOwned<CFDataRef> der(SecCertificateCopyData(cert.get()));
        if (!der)
            continue;
        std::array<unsigned char, 20> digest{};
        const bool hashed = sha1_digest(CFDataGetBytePtr(der.get()),
                                        static_cast<size_t>(CFDataGetLength(der.get())), digest);
        if (hashed && std::equal(digest.begin(), digest.end(), wanted.begin(), wanted.end())) {
            // CFArrayGetValueAtIndex does not retain — take our own reference
            // before `candidates` (and its retain on every element) releases
            // at the end of this function.
            out_identity.reset(static_cast<SecIdentityRef>(const_cast<void*>(CFRetain(identity))));
            spdlog::info("Found certificate in login keychain by thumbprint: {}", thumbprint_hex);
            return true;
        }
    }
    err = "No certificate found with thumbprint '" + thumbprint_hex + "' in the login keychain";
    return false;
}

} // namespace

CertStoreResult read_cert_from_store(const std::string& /*store_name*/, const std::string& subject,
                                     const std::string& thumbprint) {
    CertStoreResult result;

    if (subject.empty() && thumbprint.empty()) {
        result.error = "Either --cert-subject or --cert-thumbprint is required with --cert-store";
        return result;
    }

    // Disable ALL Keychain UI for the rest of this process before touching a
    // single Sec* API. kSecUseAuthenticationUIFail (below, on every
    // SecItemCopyMatching query) covers the identity/certificate lookups,
    // but SecIdentityCopyPrivateKey() and SecItemExport() — both called
    // after a lookup already succeeded — take no per-call UI option of their
    // own; this process-global switch is the only documented way to stop a
    // protected-ACL key or a locked keychain from summoning SecurityAgent
    // during those later calls. Deliberately never re-enabled: this daemon
    // must not show a Keychain prompt at any point in its lifetime.
    OSStatus ui_status = SecKeychainSetUserInteractionAllowed(false);
    if (ui_status != errSecSuccess) {
        result.error = "Could not disable keychain user interaction (" + describe(ui_status) +
                       "); refusing to risk an interactive prompt from a headless agent.";
        return result;
    }

    // Resolve the current user's login keychain via the documented
    // domain-default lookup — NOT SecKeychainOpen("login.keychain-db", ...).
    // SecKeychainOpen's pathName is a POSIX path with no home-directory
    // resolution for a bare filename: under launchd, whose working directory
    // is commonly "/" and not the user's home, that call resolves
    // "./login.keychain-db" relative to cwd rather than
    // ~/Library/Keychains/login.keychain-db, so a correctly provisioned
    // identity would fail to be found. SecKeychainCopyDomainDefault has no
    // such ambiguity. Never System.keychain, which needs root/TCC and can
    // prompt interactively; if the user domain default can't be opened (e.g.
    // a headless daemon with no attached login session) that is an honest
    // lookup failure — deliberately NOT a fallback to System.
    CFOwned<SecKeychainRef> login_keychain;
    OSStatus kc_status =
        SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, login_keychain.out());
    if (kc_status != errSecSuccess || !login_keychain) {
        result.error = "Could not open the login keychain (" + describe(kc_status) +
                       "). --cert-store looks only in the current user's login keychain; the "
                       "System keychain is deliberately never searched.";
        return result;
    }

    const void* kc_values[] = {login_keychain.get()};
    CFOwned<CFArrayRef> search_list(
        CFArrayCreate(kCFAllocatorDefault, kc_values, 1, &kCFTypeArrayCallBacks));
    if (!search_list) {
        result.error = "Failed to allocate a Core Foundation array for the keychain search list";
        return result;
    }

    CFOwned<SecIdentityRef> identity;
    // Thumbprint wins when both are given — same precedence as Windows.
    const bool located = !thumbprint.empty()
                             ? find_identity_by_thumbprint(search_list.get(), thumbprint, identity,
                                                           result.error)
                             : find_identity_by_subject(search_list.get(), subject, identity,
                                                        result.error);
    if (!located)
        return result;

    CFOwned<SecCertificateRef> leaf;
    OSStatus cert_st = SecIdentityCopyCertificate(identity.get(), leaf.out());
    if (cert_st != errSecSuccess || !leaf) {
        result.error = "Matched identity has no certificate: " + describe(cert_st);
        return result;
    }

    CFOwned<SecKeyRef> privkey;
    OSStatus key_st = SecIdentityCopyPrivateKey(identity.get(), privkey.out());
    if (key_st != errSecSuccess || !privkey) {
        result.error = "Matched identity has no accessible private key: " + describe(key_st) +
                       ". Ensure the key was imported as exportable.";
        return result;
    }

    // CFOwned (not a raw local + manual CFRelease) so a bad_alloc thrown out of
    // cfstring_to_utf8()/spdlog's own formatting cannot leak this reference —
    // the same exception-safety rationale as EvpMdCtxGuard above.
    CFOwned<CFStringRef> name(SecCertificateCopySubjectSummary(leaf.get()));
    if (name)
        spdlog::info("Using keychain identity: {}", cfstring_to_utf8(name.get()));

    // ── Leaf certificate ──────────────────────────────────────────────────
    std::string cert_pem;
    if (!export_cert_pem(leaf.get(), cert_pem, result.error))
        return result;

    // ── Intermediates, best-effort, login-keychain-scoped ─────────────────
    // A lone leaf with no locally-stored intermediates is still a usable
    // result — gRPC strictly needs only the leaf, and a well-provisioned
    // deployment's server-side trust anchor already has the intermediate/CA —
    // exactly the "fall back to just the leaf certificate" tolerance the
    // Windows chain-building above already has.
    //
    // This deliberately does NOT build a SecTrust to enumerate the chain:
    // SecTrustSetKeychains() stopped scoping trust evaluation in macOS
    // 10.12 — Apple's own header says so ("this function no longer affected
    // the behavior of the trust evaluation: the user's keychain search list
    // and the system anchors keychain are searched") — so a SecTrust-built
    // chain can silently pull an intermediate from another user keychain or
    // the System Roots keychain, breaking the "login keychain only" contract
    // this function documents. Instead, walk the issuer relationship by hand
    // using ONLY certificates a login-scoped SecItemCopyMatching proves live
    // in this keychain: repeatedly find the certificate whose normalized
    // SUBJECT equals the current certificate's normalized ISSUER — the same
    // relationship SecTrust chain-building uses internally, but sourced
    // exclusively from this function's own login-scoped query — capped at a
    // sane depth so a malformed or cyclic keychain can never spin this loop.
    // No network fetch is ever enabled, so this never leaves the local
    // keychain either way.
    {
        CFOwned<CFMutableDictionaryRef> cert_query(CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks));
        if (cert_query) {
            CFDictionarySetValue(cert_query.get(), kSecClass, kSecClassCertificate);
            CFDictionarySetValue(cert_query.get(), kSecMatchSearchList, search_list.get());
            CFDictionarySetValue(cert_query.get(), kSecMatchLimit, kSecMatchLimitAll);
            CFDictionarySetValue(cert_query.get(), kSecReturnRef, kCFBooleanTrue);
            CFDictionarySetValue(cert_query.get(), kSecUseAuthenticationUI,
                                 kSecUseAuthenticationUIFail);

            CFTypeRef raw_certs = nullptr;
            OSStatus certs_st = SecItemCopyMatching(cert_query.get(), &raw_certs);
            if (certs_st == errSecSuccess && raw_certs != nullptr) {
                CFOwned<CFArrayRef> candidates(
                    static_cast<CFArrayRef>(const_cast<void*>(raw_certs)));
                const CFIndex n_candidates = CFArrayGetCount(candidates.get());

                CFOwned<CFDataRef> want_issuer(
                    SecCertificateCopyNormalizedIssuerSequence(leaf.get()));
                constexpr int kMaxChainDepth = 8; // generous; real chains run 1-3 deep
                SecCertificateRef prev_match = nullptr; // cycle guard, not owned
                for (int depth = 0; depth < kMaxChainDepth && want_issuer; ++depth) {
                    SecCertificateRef match = nullptr;
                    for (CFIndex i = 0; i < n_candidates; ++i) {
                        auto cand = static_cast<SecCertificateRef>(const_cast<void*>(
                            CFArrayGetValueAtIndex(candidates.get(), i)));
                        // Never re-match the leaf itself: for a self-signed
                        // leaf (subject == issuer), the very first search
                        // below would otherwise find the leaf as its own
                        // "issuer" and re-export it as a spurious duplicate
                        // intermediate. CFEqual compares certificate content,
                        // not pointer identity — `cand` came from this
                        // function's own SecItemCopyMatching call, a
                        // different SecCertificateRef instance than `leaf`
                        // even when it is the exact same certificate.
                        if (CFEqual(cand, leaf.get()))
                            continue;
                        CFOwned<CFDataRef> cand_subject(
                            SecCertificateCopyNormalizedSubjectSequence(cand));
                        if (cand_subject && CFEqual(cand_subject.get(), want_issuer.get())) {
                            match = cand;
                            break;
                        }
                    }
                    if (match == nullptr || match == prev_match)
                        break; // no issuer found locally, or a self-referential loop
                    prev_match = match;

                    std::string inter_pem, inter_err;
                    if (export_cert_pem(match, inter_pem, inter_err))
                        cert_pem += inter_pem;

                    CFOwned<CFDataRef> match_subject(
                        SecCertificateCopyNormalizedSubjectSequence(match));
                    CFOwned<CFDataRef> match_issuer(
                        SecCertificateCopyNormalizedIssuerSequence(match));
                    if (match_subject && match_issuer &&
                        CFEqual(match_subject.get(), match_issuer.get()))
                        break; // self-signed — this is the root, chain is complete
                    want_issuer = std::move(match_issuer);
                }
            }
        }
    }
    result.pem_cert_chain = std::move(cert_pem);

    // ── Private key ─────────────────────────────────────────────────────
    std::string key_pem;
    if (!export_key_pem(privkey.get(), key_pem, result.error))
        return result;
    result.pem_private_key = std::move(key_pem);

    return result;
    // Every CFOwned<> member declared above releases its Sec*/CF reference
    // here, in reverse declaration order, on every return path including the
    // early-exit ones above.
}

} // namespace yuzu::agent

#else // !YUZU_HAVE_SECURITY — Security.framework not found at configure time

namespace yuzu::agent {

CertStoreResult read_cert_from_store(const std::string& /*store_name*/,
                                     const std::string& /*subject*/,
                                     const std::string& /*thumbprint*/) {
    return CertStoreResult{.error =
                               "macOS keychain identity support was not compiled into this "
                               "build (Security.framework was not found at configure time). "
                               "Use --client-cert and --client-key with PEM files instead."};
}

} // namespace yuzu::agent

#endif // YUZU_HAVE_SECURITY

#else // Linux (and any other non-Windows, non-Apple target) — PEM files only

namespace yuzu::agent {

CertStoreResult read_cert_from_store(const std::string& /*store_name*/,
                                     const std::string& /*subject*/,
                                     const std::string& /*thumbprint*/) {
    return CertStoreResult{.error =
                               "OS certificate store integration is only available on Windows "
                               "and macOS. Use --client-cert and --client-key with PEM files "
                               "instead."};
}

} // namespace yuzu::agent

#endif // _WIN32 / __APPLE__
