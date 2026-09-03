#include "ota_signature_sidecar.hpp"

#include <fstream>
#include <iterator>
#include <system_error>
#include <string_view>

namespace yuzu::server {

std::filesystem::path signature_sidecar_path(const std::filesystem::path& binary) {
    auto p = binary;
    p += ".sig";
    return p;
}

SidecarOutcome read_signature_sidecar(const std::filesystem::path& sidecar, std::string& out) {
    out.clear();

    std::error_code exists_ec;
    const bool present = std::filesystem::exists(sidecar, exists_ec);
    if (exists_ec) {
        // A FAILED existence check is not an absence. EACCES or EIO on the parent
        // directory would otherwise read as "unsigned" silently, and under
        // --update-require-signature the fleet then refuses the package with no
        // server-side cause to point at.
        return SidecarOutcome::kUnreadable;
    }
    if (!present)
        return SidecarOutcome::kAbsent;

    // A SEPARATE error_code from the exists() call above: reusing one meant a
    // FAILED file_size left the cap branch unentered and fell through to an
    // unbounded read — the exact case the cap exists for.
    std::error_code size_ec;
    const auto size = std::filesystem::file_size(sidecar, size_ec);
    if (size_ec || size > kMaxSignatureBytes)
        return SidecarOutcome::kOverCap;

    std::ifstream in(sidecar, std::ios::binary);
    if (!in)
        return SidecarOutcome::kUnreadable;

    out.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (out.empty()) {
        // A zero-byte sidecar is NOT a signature. Served as-is it would put an
        // empty string on the wire, which the agent reads as ABSENT — so in
        // permissive mode it applies the binary UNVERIFIED while the operator's
        // Signed column, reading only existence, says "signed". Refuse it here so
        // both surfaces agree and the operator gets a log line.
        out.clear();
        return SidecarOutcome::kUnreadable;
    }
    return SidecarOutcome::kServed;
}

namespace {

/// Remove the staging file only.
///
/// DELIBERATELY NOT the surviving predecessor. Enumerating the windows shows why:
/// old-binary + new-signature fails closed; new-binary + old-signature fails
/// closed; new-binary + NO signature is the one unsafe state, because a permissive
/// agent applies it UNVERIFIED. So destroying a signature must be an operator's
/// explicit choice to upload unsigned — never a failure recovery.
///
/// The concrete case: on Windows a concurrent CheckForUpdate holds the sidecar
/// open without FILE_SHARE_DELETE, so the rename fails with a sharing violation.
/// Removing the predecessor there would silently strip a VALID signature during
/// an ordinary re-upload, and permissive agents would then apply the new binary
/// unverified. Leaving it makes them refuse instead, which is the safe direction,
/// and the caller reports the failure so the operator knows to retry.
void discard_staging(const std::filesystem::path& tmp) {
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
}

} // namespace

SidecarOutcome signature_sidecar_outcome(const std::filesystem::path& sidecar) {
    // Deliberately delegates rather than duplicating the ladder: two copies of
    // "is this servable" is exactly how the column and the server came to
    // disagree in the first place. The discarded buffer is the price of one
    // decision site, and it is paid only on the settings fragment.
    std::string ignored;
    return read_signature_sidecar(sidecar, ignored);
}

bool looks_like_pem_cms(const std::string& signature_pem) {
    // Accept both armour spellings OpenSSL emits for a detached CMS signature:
    // `CMS` from `openssl cms -sign`, `PKCS7` from the older `smime`/`pkcs7`
    // tooling. Both are what `CMS_verify` consumes, so refusing either at upload
    // would reject signatures the agent would have accepted.
    static constexpr std::string_view kHeaders[] = {"-----BEGIN CMS-----",
                                                    "-----BEGIN PKCS7-----"};
    for (const auto header : kHeaders) {
        const auto begin = signature_pem.find(header);
        if (begin == std::string::npos)
            continue;
        // The matching footer must follow the header, so a file carrying only an
        // armour line, or a truncated upload, is still rejected.
        std::string footer("-----END ");
        footer.append(header.substr(std::string_view("-----BEGIN ").size()));
        return signature_pem.find(footer, begin + header.size()) != std::string::npos;
    }
    return false;
}

bool replace_signature_sidecar(const std::filesystem::path& sidecar,
                               const std::string& signature_pem) {
    if (signature_pem.empty()) {
        // Genuinely unsigned now: remove any predecessor. This is the case that
        // must never be skipped — see the header.
        std::error_code stale_ec;
        std::filesystem::remove(sidecar, stale_ec);
        return true;
    }

    // ATOMIC REPLACE, not remove-then-write. CheckForUpdate reads this path
    // concurrently, so a remove followed by a write publishes a window in which
    // the package is served UNSIGNED — brief, but an agent that polls inside it
    // is refused under --update-require-signature, and the operator sees a
    // spurious refusal with no cause to point at. Writing a sibling and renaming
    // means a reader sees either the old signature or the new one, never neither.
    auto tmp = sidecar;
    tmp += ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (out)
            out.write(signature_pem.data(), static_cast<std::streamsize>(signature_pem.size()));
        if (!out) {
            discard_staging(tmp);
            return false;
        }
    } // closed before the rename: a rename over an open handle is not portable

    std::error_code ren_ec;
    std::filesystem::rename(tmp, sidecar, ren_ec);
    if (ren_ec) {
        discard_staging(tmp);
        return false;
    }
    return true;
}

} // namespace yuzu::server
