// security_headers.cpp — implementation of HTTP security response headers (SOC2-C1).

#include "security_headers.hpp"

#include <httplib.h>

#include <format>

namespace yuzu::server::security {

namespace {

// Strict allow-list of CSP source-expression keywords that operators may pass
// via --csp-extra-sources. Deliberately excludes 'unsafe-inline',
// 'unsafe-eval', 'strict-dynamic', and 'wasm-unsafe-eval' — these all weaken
// the browser's enforcement and should not be enabled by an
// operationally-flagged extension. If a deployment genuinely needs them, the
// build itself should be modified.
constexpr std::string_view kSafeKeywords[] = {
    "'self'",
    "'none'",
};

// Hash and nonce expressions are pinned to specific content, so they're safe
// to allow operators to add via the flag.
[[nodiscard]] bool is_hash_or_nonce(std::string_view token) {
    return token.starts_with("'sha256-") || token.starts_with("'sha384-") ||
           token.starts_with("'sha512-") || token.starts_with("'nonce-");
}

[[nodiscard]] bool is_safe_keyword(std::string_view token) {
    for (auto kw : kSafeKeywords) {
        if (token == kw) return true;
    }
    return false;
}

// Validate a single space-separated token from --csp-extra-sources.
[[nodiscard]] bool is_valid_token(std::string_view token) {
    if (token.empty()) return false;

    // Reject directive separators and list separators inside a token.
    // (Whitespace can't appear because we already split on it.)
    if (token.find(';') != std::string_view::npos) return false;
    if (token.find(',') != std::string_view::npos) return false;

    // Quoted tokens: must be balanced and on the safe allow-list.
    const bool starts_quoted = token.front() == '\'';
    const bool ends_quoted = token.back() == '\'';
    if (starts_quoted || ends_quoted) {
        if (!starts_quoted || !ends_quoted || token.size() < 2) return false;
        return is_safe_keyword(token) || is_hash_or_nonce(token);
    }

    // Unquoted tokens must not contain a stray single quote (malformed).
    if (token.find('\'') != std::string_view::npos) return false;

    // Otherwise: any printable ASCII source expression (scheme, host,
    // scheme://host[:port][/path], wildcard host like *.example.com).
    // The control-byte check at the top of validate_csp_extra_sources has
    // already rejected anything with C0/C1/DEL.
    return true;
}

} // namespace

std::expected<std::string, std::string>
validate_csp_extra_sources(std::string_view raw) {
    if (raw.empty()) return std::string{};

    // 1. Reject control bytes anywhere — these cause cpp-httplib's
    //    is_field_value check to drop the header silently, leaving every
    //    response with no CSP (the silent-failure path the chaos analysis
    //    flagged in UP-1). Allow 0x09 (tab) and 0x20 (space) as token
    //    separators, matching cpp-httplib's is_field_value grammar
    //    (RFC 9110 §5.5: VCHAR / SP / HTAB).
    for (std::size_t i = 0; i < raw.size(); ++i) {
        const auto uc = static_cast<unsigned char>(raw[i]);
        if (uc == 0x09 || uc == 0x20) continue; // SP / HTAB allowed
        if (uc < 0x20 || uc == 0x7F) {
            return std::unexpected(std::format(
                "csp_extra_sources contains forbidden control byte 0x{:02x} "
                "at position {}",
                static_cast<unsigned>(uc), i));
        }
    }

    // 2. Tokenize on ASCII whitespace and validate each token.
    std::string normalized;
    normalized.reserve(raw.size());
    std::size_t pos = 0;
    while (pos < raw.size()) {
        while (pos < raw.size() && (raw[pos] == ' ' || raw[pos] == '\t')) ++pos;
        if (pos >= raw.size()) break;

        const std::size_t start = pos;
        while (pos < raw.size() && raw[pos] != ' ' && raw[pos] != '\t') ++pos;
        const std::string_view token = raw.substr(start, pos - start);

        if (!is_valid_token(token)) {
            return std::unexpected(std::format(
                "csp_extra_sources token \"{}\" is not a valid CSP source "
                "expression (allowed: scheme://host, scheme:, host, *.host, "
                "'self', 'none', 'sha256-...', 'sha384-...', 'sha512-...', "
                "'nonce-...')",
                std::string(token)));
        }

        if (!normalized.empty()) normalized += ' ';
        normalized.append(token);
    }

    return normalized;
}

std::string build_csp(std::string_view extra_sources, bool https_enabled) {
    // Build a single " <extras>" suffix once and reuse it across the four
    // directives that accept extras. Empty input → empty suffix → no stray
    // whitespace anywhere in the output.
    std::string extra;
    if (!extra_sources.empty()) {
        extra.reserve(extra_sources.size() + 1);
        extra += ' ';
        extra.append(extra_sources);
    }

    std::string csp;
    csp.reserve(640);
    csp += "default-src 'self'; ";
    csp += "script-src 'self' 'unsafe-inline' https://unpkg.com";
    csp += extra;
    csp += "; ";
    csp += "style-src 'self' 'unsafe-inline'";
    csp += extra;
    csp += "; ";
    csp += "img-src 'self' data:";
    csp += extra;
    csp += "; ";
    csp += "connect-src 'self'";
    csp += extra;
    csp += "; ";
    csp += "font-src 'self' data:; ";
    csp += "object-src 'none'; ";
    csp += "frame-ancestors 'none'; ";
    csp += "base-uri 'self'; ";
    csp += "form-action 'self'";
    if (https_enabled) {
        // Auto-upgrade any inadvertent http:// references to https:// when
        // we're serving over HTTPS. Mixed-content references would otherwise
        // be silently blocked by the browser; this fixes them up. We don't
        // emit it on HTTP-only deployments because there's nothing to upgrade
        // to and it confuses some legacy environments.
        csp += "; upgrade-insecure-requests";
    }
    return csp;
}

std::string build_permissions_policy() {
    // Deny-all baseline for browser feature APIs that the Yuzu dashboard
    // never uses. fullscreen=(self) is permitted because chart libraries and
    // future video walls may use it from the same origin.
    return "accelerometer=(), autoplay=(), camera=(), display-capture=(), "
           "encrypted-media=(), fullscreen=(self), geolocation=(), "
           "gyroscope=(), magnetometer=(), microphone=(), midi=(), "
           "payment=(), picture-in-picture=(), publickey-credentials-get=(), "
           "screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), "
           "xr-spatial-tracking=()";
}

std::string build_referrer_policy() {
    // Send only the origin (not the full URL) when navigating cross-origin.
    // Same-origin navigations still get the full referrer for analytics.
    return "strict-origin-when-cross-origin";
}

HeaderBundle HeaderBundle::make(std::string_view validated_extras,
                                bool https_enabled) {
    return HeaderBundle{
        .csp = build_csp(validated_extras, https_enabled),
        .permissions_policy = build_permissions_policy(),
        .referrer_policy = build_referrer_policy(),
        .https_enabled = https_enabled,
    };
}

void HeaderBundle::apply(httplib::Response& res) const {
    res.set_header("Content-Security-Policy", csp);
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("X-Content-Type-Options", "nosniff");
    res.set_header("Referrer-Policy", referrer_policy);
    res.set_header("Permissions-Policy", permissions_policy);
    if (https_enabled) {
        // RFC 6797 §7.2: HSTS over HTTP is ignored by browsers, so we only
        // bother sending it on HTTPS deployments.
        res.set_header("Strict-Transport-Security",
                       "max-age=31536000; includeSubDomains");
    }
}

} // namespace yuzu::server::security
