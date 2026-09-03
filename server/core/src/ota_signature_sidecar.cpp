#include "ota_signature_sidecar.hpp"

#include <fstream>
#include <iterator>
#include <system_error>

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

/// Remove BOTH the staging file and any surviving predecessor.
///
/// The binary is overwritten in place BEFORE this runs, so leaving the previous
/// `.sig` behind on a failure leaves a signature over bytes that no longer exist
/// — which every anchored agent then refuses, in both enforcement modes, making
/// that package permanently undeliverable. Removing the predecessor leaves the
/// package honestly unsigned instead, which is what the caller reports.
void discard_both(const std::filesystem::path& tmp, const std::filesystem::path& sidecar) {
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
    ec.clear();
    std::filesystem::remove(sidecar, ec);
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
            discard_both(tmp, sidecar);
            return false;
        }
    } // closed before the rename: a rename over an open handle is not portable

    std::error_code ren_ec;
    std::filesystem::rename(tmp, sidecar, ren_ec);
    if (ren_ec) {
        discard_both(tmp, sidecar);
        return false;
    }
    return true;
}

} // namespace yuzu::server
