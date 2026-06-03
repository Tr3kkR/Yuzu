#include "mfa_qr.hpp"

#include "qrcodegen.hpp"

#include <spdlog/spdlog.h>

#include <exception>
#include <format>
#include <iterator>
#include <string>

namespace yuzu::server {

std::string otpauth_qr_svg(const std::string& uri) {
    using qrcodegen::QrCode;
    try {
        // QUARTILE error correction balances scan reliability against matrix
        // size for a moderately long otpauth:// URI. encodeText throws
        // data_too_long (std::length_error) if the string cannot fit any QR
        // version.
        const QrCode qr = QrCode::encodeText(uri.c_str(), QrCode::Ecc::QUARTILE);
        const int size = qr.getSize();
        constexpr int kBorder = 4; // standard QR quiet zone, in modules
        const int dim = size + kBorder * 2;

        std::string svg;
        // Each dark module emits a ~14-byte `M{x},{y}h1v1h-1z` op; ~half the
        // modules are dark, so ~size*size*10 is a safe single-allocation bound
        // (governance cpp-expert S-1; the previous size*size under-reserved ~9x).
        svg.reserve(static_cast<std::size_t>(size) * size * 10 + 256);
        // viewBox is in module units; the rendered width/height (CSS-overridable)
        // scales it crisply. White background tile + black modules so it scans
        // against the dark theme. role/aria-label for accessibility.
        std::format_to(std::back_inserter(svg),
                       "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {0} {0}\" "
                       "width=\"190\" height=\"190\" shape-rendering=\"crispEdges\" role=\"img\" "
                       "aria-label=\"MFA enrollment QR code\">"
                       "<rect width=\"{0}\" height=\"{0}\" fill=\"#ffffff\"/>"
                       "<path fill=\"#000000\" d=\"",
                       dim);
        for (int y = 0; y < size; ++y) {
            for (int x = 0; x < size; ++x) {
                if (qr.getModule(x, y)) {
                    // Direct appends via format_to — no per-module operator+
                    // temporaries (governance cpp-expert S-2).
                    std::format_to(std::back_inserter(svg), "M{},{}h1v1h-1z", x + kBorder,
                                   y + kBorder);
                }
            }
        }
        svg += "\"/></svg>";
        return svg;
    } catch (const std::exception& e) {
        // Encoding failed (input too long, or — in an OOM — an allocation
        // failure). Return empty so the caller renders the textual secret
        // fallback: enrollment must not break on a QR-render failure. Narrowed
        // from catch(...) so a foreign (non-std) throw still propagates
        // (governance cpp-expert N-1 / cpp-safety). Logged at debug for
        // observability (security INFO).
        spdlog::debug("otpauth_qr_svg: QR render failed, falling back to text secret: {}",
                      e.what());
        return {};
    }
}

} // namespace yuzu::server
