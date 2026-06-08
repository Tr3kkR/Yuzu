#pragma once

// Real SHA-256 integrity verification for runtime-loaded CVE rule files.
//
// Threat model: this verifies the staged rules file's SHA-256 against the
// digest recorded in its sidecar "<file>.sha256". It detects corruption and
// truncation in transit and at rest. It is NOT, on its own, a tamper-proof
// control: an attacker who can write the staged rules file can also write the
// adjacent sidecar. Tamper resistance for the delivery path is provided by the
// content_dist plugin, which records the operator-supplied expected hash in a
// separate KV store outside the staging directory (#808). This load-time check
// is defence-in-depth against accidental corruption, and the foundation for a
// future check against that out-of-band hash (tracked as a follow-up).

#include <array>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>

#include <openssl/evp.h>

namespace yuzu::vuln {

// Compute the lowercase-hex SHA-256 of a file's raw bytes.
// Returns true on success and writes 64 hex chars to out_hex; false on any
// I/O or crypto error (out_hex is left unspecified on failure).
inline bool sha256_file_hex(const std::string& path, std::string& out_hex) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return false;

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                               &EVP_MD_CTX_free);
    if (!ctx)
        return false;

    bool ok = EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) == 1;
    if (ok) {
        std::array<char, 8192> buf{};
        while (f) {
            f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            auto got = f.gcount();
            if (got > 0 &&
                EVP_DigestUpdate(ctx.get(), buf.data(), static_cast<size_t>(got)) != 1) {
                ok = false;
                break;
            }
        }
        if (f.bad())
            ok = false;
    }

    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int dlen = 0;
    if (ok)
        ok = EVP_DigestFinal_ex(ctx.get(), digest, &dlen) == 1;

    if (!ok || dlen != 32)
        return false;

    static constexpr char kHex[] = "0123456789abcdef";
    out_hex.clear();
    out_hex.reserve(64);
    for (unsigned i = 0; i < dlen; ++i) {
        out_hex += kHex[digest[i] >> 4];
        out_hex += kHex[digest[i] & 0x0F];
    }
    return true;
}

// Length-independent, branch-light comparison of two hex digests
// (case-insensitive). Avoids leaking match position via early return.
inline bool hex_digest_equal(std::string_view a, std::string_view b) {
    if (a.size() != b.size())
        return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        unsigned char ca = static_cast<unsigned char>(a[i]);
        unsigned char cb = static_cast<unsigned char>(b[i]);
        if (ca >= 'A' && ca <= 'F')
            ca = static_cast<unsigned char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'F')
            cb = static_cast<unsigned char>(cb - 'A' + 'a');
        diff |= static_cast<unsigned char>(ca ^ cb);
    }
    return diff == 0;
}

// Verify rules_path against the digest in "<rules_path>.sha256".
// Sidecar format: "<hex_digest>  <filename>" (the leading whitespace-delimited
// token is the digest). Returns true only when the file's computed SHA-256
// equals the recorded digest.
inline bool verify_rules_sha256(const std::string& rules_path) {
    std::ifstream sha_f(rules_path + ".sha256");
    if (!sha_f)
        return false;
    std::string line;
    if (!std::getline(sha_f, line))
        return false;

    auto tok_end = line.find_first_of(" \t");
    std::string_view expected = (tok_end == std::string::npos)
                                    ? std::string_view(line)
                                    : std::string_view(line).substr(0, tok_end);
    if (expected.size() != 64)
        return false;

    std::string actual;
    if (!sha256_file_hex(rules_path, actual))
        return false;
    return hex_digest_equal(actual, expected);
}

} // namespace yuzu::vuln
