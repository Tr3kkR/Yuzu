#pragma once

/// @file ota_signature_sidecar.hpp
///
/// The detached-signature sidecar's lifecycle, as PURE decisions (#416/#3807).
///
/// WHY IT IS SEPARATE. The two call sites that move a signature from an operator's
/// upload to an agent's `CheckForUpdate` response both live behind Postgres —
/// `settings_routes.cpp`'s upload handler needs a multipart request the test route
/// sink cannot build, and `agent_service_impl.cpp`'s reader needs an
/// `UpdateRegistry`, which needs a `PgPool`. So the ~200 production lines carrying
/// the signature end to end had NO discriminating test, which two independent
/// external reviewers found in the same round. The decisions live here instead,
/// where they are testable with a temp directory and nothing else; the call sites
/// keep only the I/O they cannot avoid.

#include <cstddef>
#include <filesystem>
#include <string>

namespace yuzu::server {

/// Upper bound on a package's detached signature.
///
/// A PEM CMS detached signature is a few KB — a signer certificate chain plus one
/// digest. The cap is not about disk: this blob is attached to EVERY
/// CheckForUpdateResponse, and gRPC clients default to a 4 MB receive limit, so a
/// wrong file uploaded into the signature field would push that response past the
/// limit and break update checks for the whole fleet at once.
inline constexpr std::size_t kMaxSignatureBytes = 64 * 1024;

/// Why a sidecar was not served. Anything but `kServed` means the package is
/// offered to agents as UNSIGNED — never as an error, because whether an unsigned
/// package is acceptable is the AGENT's decision, not this server's.
enum class SidecarOutcome {
    kServed,
    kAbsent,     ///< the ordinary unsigned case
    kOverCap,    ///< larger than kMaxSignatureBytes, or a size we cannot determine
    kUnreadable, ///< present but could not be opened
};

/// The sidecar path for a package binary. Derived from the binary path, never from
/// a separately-supplied name: the filename is operator-controlled, and letting the
/// signature location be named independently would let one package point at
/// another's signature.
[[nodiscard]] std::filesystem::path signature_sidecar_path(const std::filesystem::path& binary);

/// Read the sidecar if it may be served, into `out`.
///
/// SIZE IS CHECKED BEFORE ANYTHING IS OPENED. Constructing the stream first would
/// defeat the check: `open(2)` on a FIFO blocks until a writer appears, so a FIFO
/// named `<package>.sig` would wedge the CheckForUpdate handler thread — one wedged
/// thread per agent check — before the cap was ever consulted. A size we cannot
/// determine is therefore treated as over-cap rather than probed.
[[nodiscard]] SidecarOutcome read_signature_sidecar(const std::filesystem::path& sidecar,
                                                    std::string& out);

/// The same decision without the read, for callers that only need the verdict.
///
/// The Settings packages table renders one row per package and needs only
/// "would this be served?"; going through the reading form made it pull up to
/// 64 KB per package per render and throw it away.
[[nodiscard]] SidecarOutcome signature_sidecar_outcome(const std::filesystem::path& sidecar);

/// Replace the sidecar beside a freshly-uploaded binary.
///
/// THE REMOVE IS UNCONDITIONAL and is the reason this is one function rather than
/// two. The binary is overwritten in place, so an operator re-uploading a rebuilt
/// package under the same filename WITHOUT a signature would otherwise leave the
/// previous `.sig` on disk — a signature over bytes that no longer exist. Every
/// anchored agent would then refuse the package, in both enforcement modes, and
/// rotating a signing key is exactly the sequence that walks into it.
///
/// Returns false only when a NON-EMPTY signature could not be written; the sidecar
/// is then removed again, so the package is left honestly unsigned rather than
/// carrying a partial signature.
[[nodiscard]] bool replace_signature_sidecar(const std::filesystem::path& sidecar,
                                             const std::string& signature_pem);

} // namespace yuzu::server
