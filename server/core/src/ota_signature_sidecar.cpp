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
    if (!std::filesystem::exists(sidecar, exists_ec) || exists_ec)
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
    return SidecarOutcome::kServed;
}

bool replace_signature_sidecar(const std::filesystem::path& sidecar,
                               const std::string& signature_pem) {
    std::error_code stale_ec;
    std::filesystem::remove(sidecar, stale_ec);

    if (signature_pem.empty())
        return true; // the package is now honestly unsigned

    std::ofstream out(sidecar, std::ios::binary | std::ios::trunc);
    if (out)
        out.write(signature_pem.data(), static_cast<std::streamsize>(signature_pem.size()));
    if (!out) {
        std::error_code rm_ec;
        std::filesystem::remove(sidecar, rm_ec);
        return false;
    }
    return true;
}

} // namespace yuzu::server
