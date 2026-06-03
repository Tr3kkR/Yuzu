#pragma once

#include <string>

namespace yuzu::server {

/// Render an `otpauth://` URI (or any text) as a self-contained inline SVG QR
/// code — dark modules on a white tile with the standard 4-module quiet zone,
/// so it scans reliably even on the dark dashboard. Server-side rendering keeps
/// the dashboard's no-client-JS / no-CDN convention (issue #1232).
///
/// Returns an empty string if encoding fails (e.g. the input is too long for a
/// QR symbol); callers MUST fall back to the textual secret in that case so
/// enrollment never breaks on a render failure.
std::string otpauth_qr_svg(const std::string& uri);

} // namespace yuzu::server
