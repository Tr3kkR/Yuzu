#pragma once

/// @file plugin_signing_helpers.hpp
/// Helpers for the operator-managed plugin code-signing trust bundle —
/// PEM validation + on-disk path. Lives outside settings_routes.cpp so it
/// can be unit-tested without spinning up the full Settings route surface.

#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::plugin_signing {

constexpr const char* kPluginTrustBundleFilename = "plugin-trust-bundle.pem";

/// Default on-disk location: auth::default_cert_dir() / kPluginTrustBundleFilename.
/// Defined in plugin_signing_helpers.cpp so callers do not have to pull
/// `<yuzu/server/auth.hpp>` for this single use.
[[nodiscard]] std::filesystem::path trust_bundle_path();

struct TrustBundleStats {
    int cert_count{0};
    std::string sha256_hex;
    std::vector<std::string> subjects; // human-readable CN/O for display
};

/// Validate uploaded PEM bytes: parse every embedded X.509 cert, count
/// them, hash the raw PEM bytes (operator-facing fingerprint), and
/// extract subject lines for display. Returns an error message suitable
/// for the operator UI on failure (empty input, missing markers, no
/// parsable cert, or OpenSSL hashing failure).
[[nodiscard]] std::expected<TrustBundleStats, std::string>
validate_trust_bundle_pem(std::string_view pem);

} // namespace yuzu::server::plugin_signing
