#include "oidc_provider.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <cstdio>
#include <sstream>

#ifdef _WIN32
// clang-format off
#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>
// clang-format on
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")
#else
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

namespace yuzu::server::oidc {

// ── Platform crypto (file-local) ─────────────────────────────────────────────

static std::vector<uint8_t> random_bytes(std::size_t n) {
    std::vector<uint8_t> buf(n);
#ifdef _WIN32
    auto status = BCryptGenRandom(nullptr, buf.data(), static_cast<ULONG>(n),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status))
        throw std::runtime_error("BCryptGenRandom failed");
#else
    if (RAND_bytes(buf.data(), static_cast<int>(n)) != 1)
        throw std::runtime_error("RAND_bytes failed");
#endif
    return buf;
}

static std::string bytes_to_hex(const std::vector<uint8_t>& v) {
    std::string out;
    out.reserve(v.size() * 2);
    for (auto b : v) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", b);
        out.append(buf, 2);
    }
    return out;
}

static std::vector<uint8_t> sha256_raw(const std::string& input) {
    std::vector<uint8_t> hash(32);
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    BCRYPT_HASH_HANDLE hHash = nullptr;
    BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                   static_cast<ULONG>(input.size()), 0);
    BCryptFinishHash(hHash, hash.data(), static_cast<ULONG>(hash.size()), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, hash.data(), nullptr);
    EVP_MD_CTX_free(ctx);
#endif
    return hash;
}

// ── Base64URL ────────────────────────────────────────────────────────────────

std::string OidcProvider::base64url_encode(const std::vector<uint8_t>& data) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string out;
    out.reserve((data.size() + 2) / 3 * 4);

    for (std::size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < data.size()) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < data.size()) n |= static_cast<uint32_t>(data[i + 2]);

        out += kAlphabet[(n >> 18) & 0x3F];
        out += kAlphabet[(n >> 12) & 0x3F];
        if (i + 1 < data.size()) out += kAlphabet[(n >> 6) & 0x3F];
        if (i + 2 < data.size()) out += kAlphabet[n & 0x3F];
    }
    // No padding (JWT convention)
    return out;
}

std::string OidcProvider::base64url_decode(const std::string& input) {
    // Convert base64url to standard base64 and decode
    std::string b64 = input;
    for (auto& c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    // Add padding
    while (b64.size() % 4 != 0)
        b64 += '=';

    // Standard base64 decode
    static constexpr unsigned char kTable[256] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62,
        64, 64, 64, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0,
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64};

    std::string out;
    out.reserve(b64.size() * 3 / 4);
    unsigned int val = 0;
    int bits = -8;
    for (unsigned char c : b64) {
        if (kTable[c] == 64) continue;
        val = (val << 6) | kTable[c];
        bits += 6;
        if (bits >= 0) {
            out += static_cast<char>((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return out;
}

// ── URL encoding ─────────────────────────────────────────────────────────────

std::string OidcProvider::url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (char c : value) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' ||
            c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2)
                    << static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    return escaped.str();
}

// ── PKCE ─────────────────────────────────────────────────────────────────────

std::string OidcProvider::generate_code_verifier() {
    auto bytes = random_bytes(32);
    return base64url_encode(bytes);
}

std::string OidcProvider::compute_code_challenge(const std::string& verifier) {
    auto hash = sha256_raw(verifier);
    return base64url_encode(hash);
}

// ── JWT parsing ──────────────────────────────────────────────────────────────

std::expected<IdTokenClaims, std::string>
OidcProvider::parse_id_token(const std::string& jwt) {
    // Split on '.'
    auto dot1 = jwt.find('.');
    if (dot1 == std::string::npos)
        return std::unexpected("invalid JWT: no dots");

    auto dot2 = jwt.find('.', dot1 + 1);
    if (dot2 == std::string::npos)
        return std::unexpected("invalid JWT: only one dot");

    auto payload_b64 = jwt.substr(dot1 + 1, dot2 - dot1 - 1);
    auto payload_json = base64url_decode(payload_b64);

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(payload_json);
    } catch (const nlohmann::json::parse_error& e) {
        return std::unexpected(std::string("JWT payload parse error: ") + e.what());
    }

    IdTokenClaims claims;
    if (j.contains("sub"))                claims.sub = j["sub"].get<std::string>();
    if (j.contains("email"))              claims.email = j["email"].get<std::string>();
    if (j.contains("preferred_username")) claims.preferred_username = j["preferred_username"].get<std::string>();
    if (j.contains("name"))               claims.name = j["name"].get<std::string>();
    if (j.contains("iss"))                claims.iss = j["iss"].get<std::string>();
    if (j.contains("nonce"))              claims.nonce = j["nonce"].get<std::string>();
    if (j.contains("exp"))                claims.exp = j["exp"].get<int64_t>();
    if (j.contains("iat"))                claims.iat = j["iat"].get<int64_t>();

    // aud can be a string or array
    if (j.contains("aud")) {
        if (j["aud"].is_string()) {
            claims.aud = j["aud"].get<std::string>();
        } else if (j["aud"].is_array() && !j["aud"].empty()) {
            claims.aud = j["aud"][0].get<std::string>();
        }
    }

    // groups claim: array of Entra security group object IDs
    if (j.contains("groups") && j["groups"].is_array()) {
        for (auto& g : j["groups"])
            if (g.is_string())
                claims.groups.push_back(g.get<std::string>());
    }

    return claims;
}

std::expected<void, std::string>
OidcProvider::validate_claims(const IdTokenClaims& claims,
                               const std::string& expected_nonce) const {
    if (claims.iss != config_.issuer)
        return std::unexpected("iss mismatch: got '" + claims.iss + "', expected '" +
                               config_.issuer + "'");

    if (claims.aud != config_.client_id)
        return std::unexpected("aud mismatch: got '" + claims.aud + "', expected '" +
                               config_.client_id + "'");

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    constexpr int64_t kClockSkew = 60;
    if (claims.exp > 0 && claims.exp + kClockSkew < now)
        return std::unexpected("token expired");

    if (claims.nonce != expected_nonce)
        return std::unexpected("nonce mismatch");

    return {};
}

// ── WinHTTP helper (Windows only) ────────────────────────────────────────────

#ifdef _WIN32
static std::string winhttp_post(const std::string& url, const std::string& form_body) {
    // Parse URL into components
    // Expected: https://host/path
    std::wstring wurl(url.begin(), url.end());

    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {}, path[2048] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 2048;

    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) {
        spdlog::error("WinHTTP: failed to crack URL: {}", url);
        return {};
    }

    HINTERNET session = WinHttpOpen(L"Yuzu-Server/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        spdlog::error("WinHTTP: WinHttpOpen failed: {}", GetLastError());
        return {};
    }

    HINTERNET connect = WinHttpConnect(session, host, uc.nPort, 0);
    if (!connect) {
        spdlog::error("WinHTTP: WinHttpConnect failed: {}", GetLastError());
        WinHttpCloseHandle(session);
        return {};
    }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", path, nullptr,
                                            WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        spdlog::error("WinHTTP: WinHttpOpenRequest failed: {}", GetLastError());
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return {};
    }

    const wchar_t* content_type = L"Content-Type: application/x-www-form-urlencoded";
    BOOL ok = WinHttpSendRequest(request, content_type, -1L,
                                  const_cast<char*>(form_body.data()),
                                  static_cast<DWORD>(form_body.size()),
                                  static_cast<DWORD>(form_body.size()), 0);
    if (!ok) {
        spdlog::error("WinHTTP: WinHttpSendRequest failed: {}", GetLastError());
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return {};
    }

    ok = WinHttpReceiveResponse(request, nullptr);
    if (!ok) {
        spdlog::error("WinHTTP: WinHttpReceiveResponse failed: {}", GetLastError());
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return {};
    }

    std::string response;
    DWORD bytes_available = 0;
    do {
        WinHttpQueryDataAvailable(request, &bytes_available);
        if (bytes_available > 0) {
            std::vector<char> buf(bytes_available);
            DWORD bytes_read = 0;
            WinHttpReadData(request, buf.data(), bytes_available, &bytes_read);
            response.append(buf.data(), bytes_read);
        }
    } while (bytes_available > 0);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    spdlog::info("WinHTTP: POST {} -> {} bytes", url, response.size());
    return response;
}
#endif

// ── Token exchange ───────────────────────────────────────────────────────────

std::expected<std::string, std::string>
OidcProvider::exchange_code(const std::string& code, const std::string& code_verifier,
                             const std::string& redirect_uri) {
    std::string form_body = "grant_type=authorization_code"
                            "&code=" + url_encode(code) +
                            "&redirect_uri=" + url_encode(redirect_uri) +
                            "&client_id=" + url_encode(config_.client_id) +
                            "&code_verifier=" + url_encode(code_verifier);
    if (!config_.client_secret.empty())
        form_body += "&client_secret=" + url_encode(config_.client_secret);

    spdlog::info("OIDC token exchange: endpoint={} redirect_uri={}", config_.token_endpoint,
                 redirect_uri);

    std::string response_body;

#ifdef _WIN32
    // Use WinHTTP on Windows — httplib's OpenSSL client fails from handler threads.
    response_body = winhttp_post(config_.token_endpoint, form_body);
    if (response_body.empty()) {
        spdlog::error("OIDC token exchange: WinHTTP POST failed");
        return std::unexpected("token endpoint request failed (WinHTTP)");
    }
#else
    // Parse URL for httplib
    auto url = config_.token_endpoint;
    std::string scheme, host, path;
    if (url.starts_with("https://")) { scheme = "https://"; url = url.substr(8); }
    else if (url.starts_with("http://")) { scheme = "http://"; url = url.substr(7); }
    else return std::unexpected("invalid token endpoint URL");
    auto slash = url.find('/');
    host = (slash != std::string::npos) ? url.substr(0, slash) : url;
    path = (slash != std::string::npos) ? url.substr(slash) : "/";

    httplib::Client client(scheme + host);
    client.set_connection_timeout(10);
    client.set_read_timeout(15);
    auto result = client.Post(path, form_body, "application/x-www-form-urlencoded");
    if (!result) {
        spdlog::error("OIDC token exchange: httplib failed: {}", httplib::to_string(result.error()));
        return std::unexpected("token endpoint request failed: " + httplib::to_string(result.error()));
    }
    if (result->status != 200) {
        spdlog::error("OIDC token exchange: status={} body={}", result->status,
                      result->body.substr(0, 500));
        return std::unexpected("token endpoint returned " + std::to_string(result->status));
    }
    response_body = result->body;
#endif

    spdlog::info("OIDC token exchange: response_len={}", response_body.size());

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(response_body);
    } catch (const nlohmann::json::parse_error& e) {
        spdlog::error("OIDC token exchange: parse error: {} body={}", e.what(),
                      response_body.substr(0, 500));
        return std::unexpected(std::string("token response parse error: ") + e.what());
    }

    if (j.contains("error")) {
        auto err = j["error"].get<std::string>();
        auto desc = j.value("error_description", "");
        spdlog::error("OIDC token exchange error: {} - {}", err, desc.substr(0, 300));
        return std::unexpected("token endpoint error: " + err);
    }

    if (!j.contains("id_token") || !j["id_token"].is_string())
        return std::unexpected("no id_token in token response");

    return j["id_token"].get<std::string>();
}

// ── OidcProvider ─────────────────────────────────────────────────────────────

OidcProvider::OidcProvider(OidcConfig config) : config_(std::move(config)),
    exchange_script_path_(config_.exchange_script) {
    // Fetch OIDC discovery document to get the real endpoints
    auto discovery_url = config_.issuer + "/.well-known/openid-configuration";
    spdlog::info("OidcProvider: fetching discovery from {}", discovery_url);

    // Parse host and path from discovery URL
    std::string disc_url = discovery_url;
    std::string scheme;
    if (disc_url.starts_with("https://")) {
        scheme = "https://";
        disc_url = disc_url.substr(8);
    } else if (disc_url.starts_with("http://")) {
        scheme = "http://";
        disc_url = disc_url.substr(7);
    }
    auto slash = disc_url.find('/');
    auto host = disc_url.substr(0, slash);
    auto path = disc_url.substr(slash);

    httplib::Client client(scheme + host);
    client.set_connection_timeout(15);
    client.set_read_timeout(15);
    client.enable_server_certificate_verification(false);  // Windows OpenSSL lacks system CA bundle
    auto result = client.Get(path);

    if (result && result->status == 200) {
        try {
            auto j = nlohmann::json::parse(result->body);
            if (j.contains("authorization_endpoint"))
                config_.authorization_endpoint = j["authorization_endpoint"].get<std::string>();
            if (j.contains("token_endpoint"))
                config_.token_endpoint = j["token_endpoint"].get<std::string>();
            spdlog::info("OidcProvider: authorize={}", config_.authorization_endpoint);
            spdlog::info("OidcProvider: token={}", config_.token_endpoint);
        } catch (const std::exception& e) {
            spdlog::error("OidcProvider: failed to parse discovery document: {}", e.what());
        }
    } else {
        spdlog::warn("OidcProvider: discovery fetch failed (status={}), using fallback endpoints",
                     result ? result->status : 0);
    }

    spdlog::info("OidcProvider: issuer={} client_id={}", config_.issuer, config_.client_id);
}

bool OidcProvider::is_enabled() const {
    return config_.is_enabled();
}

std::string OidcProvider::start_auth_flow(const std::string& request_redirect_uri) {
    auto verifier  = generate_code_verifier();
    auto challenge = compute_code_challenge(verifier);
    auto state     = bytes_to_hex(random_bytes(32));
    auto nonce     = bytes_to_hex(random_bytes(16));

    // Use the request-derived redirect URI if provided, otherwise fall back to config
    auto redirect_uri = request_redirect_uri.empty() ? config_.redirect_uri : request_redirect_uri;

    PkceChallenge pkce;
    pkce.code_verifier  = verifier;
    pkce.code_challenge = challenge;
    pkce.state          = state;
    pkce.nonce          = nonce;
    pkce.redirect_uri   = redirect_uri;
    pkce.expires_at     = std::chrono::steady_clock::now() + kChallengeTtl;

    {
        std::lock_guard lock(mu_);
        pending_challenges_[state] = std::move(pkce);
    }

    cleanup_expired_states();

    auto url = config_.authorization_endpoint +
               "?client_id=" + url_encode(config_.client_id) +
               "&response_type=code" +
               "&scope=" + url_encode("openid profile email") +
               "&redirect_uri=" + url_encode(redirect_uri) +
               "&state=" + url_encode(state) +
               "&nonce=" + url_encode(nonce) +
               "&code_challenge=" + url_encode(challenge) +
               "&code_challenge_method=S256";

    spdlog::debug("OIDC auth flow started: state={} redirect_uri={}", state.substr(0, 8),
                  redirect_uri);
    return url;
}

std::expected<IdTokenClaims, std::string>
OidcProvider::handle_callback(const std::string& code, const std::string& state) {
    spdlog::info("OIDC handle_callback: state={} code_len={}", state.substr(0, 8), code.size());

    PkceChallenge challenge;
    {
        std::lock_guard lock(mu_);
        spdlog::info("OIDC handle_callback: {} pending challenges", pending_challenges_.size());
        auto it = pending_challenges_.find(state);
        if (it == pending_challenges_.end()) {
            spdlog::error("OIDC handle_callback: state not found in pending challenges");
            return std::unexpected("unknown or expired state parameter");
        }

        if (std::chrono::steady_clock::now() > it->second.expires_at) {
            pending_challenges_.erase(it);
            spdlog::error("OIDC handle_callback: PKCE challenge expired");
            return std::unexpected("PKCE challenge expired");
        }

        challenge = std::move(it->second);
        pending_challenges_.erase(it);  // single-use
    }

    spdlog::info("OIDC handle_callback: found challenge, redirect_uri={}", challenge.redirect_uri);

    // Exchange code for tokens (use the same redirect_uri from the authorize step)
    auto id_token_result = exchange_code(code, challenge.code_verifier, challenge.redirect_uri);
    if (!id_token_result) {
        spdlog::error("OIDC handle_callback: token exchange failed: {}", id_token_result.error());
        return std::unexpected(id_token_result.error());
    }

    spdlog::info("OIDC handle_callback: got id_token (len={})", id_token_result->size());

    // Parse ID token
    auto claims_result = parse_id_token(*id_token_result);
    if (!claims_result) {
        spdlog::error("OIDC handle_callback: JWT parse failed: {}", claims_result.error());
        return std::unexpected(claims_result.error());
    }

    spdlog::info("OIDC handle_callback: parsed claims sub={} iss={} aud={} nonce={}",
                 claims_result->sub, claims_result->iss, claims_result->aud, claims_result->nonce);

    // Validate claims
    auto validation = validate_claims(*claims_result, challenge.nonce);
    if (!validation) {
        spdlog::error("OIDC handle_callback: claim validation failed: {}", validation.error());
        return std::unexpected(validation.error());
    }

    spdlog::info("OIDC auth succeeded: sub={} email={} name={}",
                 claims_result->sub,
                 claims_result->email.empty() ? "(none)" : claims_result->email,
                 claims_result->name.empty() ? "(none)" : claims_result->name);

    return claims_result;
}

void OidcProvider::cleanup_expired_states() {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard lock(mu_);
    for (auto it = pending_challenges_.begin(); it != pending_challenges_.end();) {
        if (now > it->second.expires_at)
            it = pending_challenges_.erase(it);
        else
            ++it;
    }
}

}  // namespace yuzu::server::oidc
