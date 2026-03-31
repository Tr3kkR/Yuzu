#include "directory_sync.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <random>
#include <shared_mutex>

#ifdef _WIN32
// clang-format off
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
// clang-format on
#endif

namespace yuzu::server {

// ── Helpers ──────────────────────────────────────────────────────────────────

namespace {

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string col_text(sqlite3_stmt* stmt, int col) {
    auto p = sqlite3_column_text(stmt, col);
    return p ? std::string(reinterpret_cast<const char*>(p)) : std::string{};
}

std::string gen_id() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    auto hi = dist(rng);
    auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx",
                  static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

std::string base64_encode(const std::string& input) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);
    for (std::size_t i = 0; i < input.size(); i += 3) {
        uint32_t n = static_cast<uint8_t>(input[i]) << 16;
        if (i + 1 < input.size())
            n |= static_cast<uint8_t>(input[i + 1]) << 8;
        if (i + 2 < input.size())
            n |= static_cast<uint8_t>(input[i + 2]);
        out += kAlphabet[(n >> 18) & 0x3F];
        out += kAlphabet[(n >> 12) & 0x3F];
        out += (i + 1 < input.size()) ? kAlphabet[(n >> 6) & 0x3F] : '=';
        out += (i + 2 < input.size()) ? kAlphabet[n & 0x3F] : '=';
    }
    return out;
}

std::string url_encode(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() * 2);
    for (char c : value) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            escaped += c;
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", static_cast<unsigned char>(c));
            escaped += buf;
        }
    }
    return escaped;
}

} // namespace

// ── Construction / teardown ──────────────────────────────────────────────────

DirectorySync::DirectorySync(const std::filesystem::path& db_path) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("DirectorySync: failed to open {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }

    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    create_tables();
    spdlog::info("DirectorySync: opened {}", db_path.string());
}

DirectorySync::~DirectorySync() {
    if (db_)
        sqlite3_close(db_);
}

bool DirectorySync::is_open() const {
    return db_ != nullptr;
}

// ── DDL ──────────────────────────────────────────────────────────────────────

void DirectorySync::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS directory_users (
            id           TEXT PRIMARY KEY,
            display_name TEXT NOT NULL DEFAULT '',
            email        TEXT NOT NULL DEFAULT '',
            upn          TEXT NOT NULL DEFAULT '',
            enabled      INTEGER NOT NULL DEFAULT 1,
            synced_at    INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS directory_groups (
            id           TEXT PRIMARY KEY,
            display_name TEXT NOT NULL DEFAULT '',
            description  TEXT NOT NULL DEFAULT '',
            mapped_role  TEXT NOT NULL DEFAULT '',
            synced_at    INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS directory_memberships (
            user_id  TEXT NOT NULL,
            group_id TEXT NOT NULL,
            PRIMARY KEY (user_id, group_id)
        );

        CREATE TABLE IF NOT EXISTS directory_group_role_mappings (
            group_id  TEXT PRIMARY KEY,
            role_name TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS directory_sync_status (
            provider     TEXT PRIMARY KEY,
            status       TEXT NOT NULL DEFAULT 'idle',
            last_sync_at INTEGER NOT NULL DEFAULT 0,
            next_sync_at INTEGER NOT NULL DEFAULT 0,
            user_count   INTEGER NOT NULL DEFAULT 0,
            group_count  INTEGER NOT NULL DEFAULT 0,
            last_error   TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_dir_users_email ON directory_users(email);
        CREATE INDEX IF NOT EXISTS idx_dir_users_upn ON directory_users(upn);
        CREATE INDEX IF NOT EXISTS idx_dir_memberships_group ON directory_memberships(group_id);
    )";

    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("DirectorySync: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

std::string DirectorySync::generate_id() const {
    return gen_id();
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

#ifdef _WIN32

// WinHTTP GET with Bearer token — used on Windows where httplib's OpenSSL
// client may fail from handler threads.
std::expected<std::string, std::string>
DirectorySync::http_get(const std::string& url, const std::string& bearer_token) {
    std::wstring wurl(url.begin(), url.end());

    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {}, path[4096] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 4096;

    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) {
        return std::unexpected("WinHTTP: failed to parse URL: " + url);
    }

    HINTERNET session = WinHttpOpen(L"Yuzu-DirectorySync/1.0",
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return std::unexpected("WinHTTP: WinHttpOpen failed");

    HINTERNET connect = WinHttpConnect(session, host, uc.nPort, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpConnect failed");
    }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"GET", path, nullptr,
                                           WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpOpenRequest failed");
    }

    // Add Authorization header
    std::wstring auth_header = L"Authorization: Bearer ";
    auth_header.append(bearer_token.begin(), bearer_token.end());
    WinHttpAddRequestHeaders(request, auth_header.c_str(),
                             static_cast<DWORD>(auth_header.size()),
                             WINHTTP_ADDREQ_FLAG_ADD);

    BOOL ok = WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!ok) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpSendRequest failed");
    }

    ok = WinHttpReceiveResponse(request, nullptr);
    if (!ok) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpReceiveResponse failed");
    }

    // Check HTTP status
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size,
                        WINHTTP_NO_HEADER_INDEX);
    if (status_code != 200) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("Graph API returned HTTP " + std::to_string(status_code));
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

    return response;
}

#else

// httplib GET with Bearer token — used on Linux/macOS.
std::expected<std::string, std::string>
DirectorySync::http_get(const std::string& url, const std::string& bearer_token) {
    // Parse scheme://host/path
    std::string u = url;
    std::string scheme;
    if (u.starts_with("https://")) {
        scheme = "https://";
        u = u.substr(8);
    } else if (u.starts_with("http://")) {
        scheme = "http://";
        u = u.substr(7);
    } else {
        return std::unexpected("invalid URL scheme: " + url);
    }

    auto slash = u.find('/');
    auto host = (slash != std::string::npos) ? u.substr(0, slash) : u;
    auto path = (slash != std::string::npos) ? u.substr(slash) : "/";

    httplib::Client client(scheme + host);
    client.set_connection_timeout(15);
    client.set_read_timeout(30);

    httplib::Headers headers = {
        {"Authorization", "Bearer " + bearer_token},
        {"Accept", "application/json"}};

    auto result = client.Get(path, headers);
    if (!result) {
        return std::unexpected("HTTP GET failed: " + httplib::to_string(result.error()));
    }
    if (result->status != 200) {
        return std::unexpected("Graph API returned HTTP " +
                               std::to_string(result->status) + ": " +
                               result->body.substr(0, 500));
    }
    return result->body;
}

#endif

// ── OAuth2 client credentials flow ──────────────────────────────────────────
//
// Per RFC 6749 Section 2.3.1, confidential clients SHOULD authenticate via
// HTTP Basic (Authorization header) rather than sending client_secret in the
// POST body.  SECURITY: The token endpoint MUST be accessed over HTTPS.

std::expected<std::string, std::string>
DirectorySync::acquire_token(const EntraConfig& config) {
    auto token_url = "https://login.microsoftonline.com/" + config.tenant_id +
                     "/oauth2/v2.0/token";

    std::string form_body =
        "grant_type=client_credentials"
        "&scope=" + url_encode("https://graph.microsoft.com/.default");

    // RFC 6749 §2.3.1: use HTTP Basic auth for client credentials
    auto credentials = base64_encode(config.client_id + ":" + config.client_secret);
    std::string auth_value = "Basic " + credentials;

    spdlog::info("DirectorySync: acquiring token from {}", token_url);

#ifdef _WIN32
    // Reuse WinHTTP POST (same pattern as OIDC provider)
    std::wstring wurl(token_url.begin(), token_url.end());

    URL_COMPONENTS uc = {};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {}, path[2048] = {};
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 2048;

    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) {
        return std::unexpected("WinHTTP: failed to parse token URL");
    }

    HINTERNET session = WinHttpOpen(L"Yuzu-DirectorySync/1.0",
                                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return std::unexpected("WinHTTP: WinHttpOpen failed");

    HINTERNET connect = WinHttpConnect(session, host, uc.nPort, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpConnect failed");
    }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", path, nullptr,
                                           WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpOpenRequest failed");
    }

    // Add HTTP Basic auth header
    std::string auth_hdr = "Authorization: " + auth_value;
    std::wstring wauth(auth_hdr.begin(), auth_hdr.end());
    WinHttpAddRequestHeaders(request, wauth.c_str(), static_cast<DWORD>(wauth.size()),
                             WINHTTP_ADDREQ_FLAG_ADD);

    const wchar_t* content_type = L"Content-Type: application/x-www-form-urlencoded";
    BOOL ok = WinHttpSendRequest(request, content_type, -1L,
                                 const_cast<char*>(form_body.data()),
                                 static_cast<DWORD>(form_body.size()),
                                 static_cast<DWORD>(form_body.size()), 0);
    if (!ok) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpSendRequest failed");
    }

    ok = WinHttpReceiveResponse(request, nullptr);
    if (!ok) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return std::unexpected("WinHTTP: WinHttpReceiveResponse failed");
    }

    std::string response_body;
    DWORD bytes_available = 0;
    do {
        WinHttpQueryDataAvailable(request, &bytes_available);
        if (bytes_available > 0) {
            std::vector<char> buf(bytes_available);
            DWORD bytes_read = 0;
            WinHttpReadData(request, buf.data(), bytes_available, &bytes_read);
            response_body.append(buf.data(), bytes_read);
        }
    } while (bytes_available > 0);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

#else
    // httplib POST for Linux/macOS
    // SECURITY: Reject non-HTTPS URLs — client secret MUST NOT be sent over plaintext
    std::string u = token_url;
    if (!u.starts_with("https://")) {
        std::fill(form_body.begin(), form_body.end(), '\0');
        return std::unexpected("token endpoint must use HTTPS (client secret protection)");
    }
    u = u.substr(8); // strip "https://"

    auto slash = u.find('/');
    auto h = (slash != std::string::npos) ? u.substr(0, slash) : u;
    auto p = (slash != std::string::npos) ? u.substr(slash) : "/";

    httplib::Client client("https://" + h);
    client.set_connection_timeout(10);
    client.set_read_timeout(15);
    // Enable TLS peer verification (httplib verifies by default with OpenSSL,
    // but set explicitly for clarity)
    client.enable_server_certificate_verification(true);

    httplib::Headers headers{{"Authorization", auth_value}};
    auto result = client.Post(p, headers, form_body, "application/x-www-form-urlencoded");
    if (!result) {
        return std::unexpected("token request failed: " +
                               httplib::to_string(result.error()));
    }
    if (result->status != 200) {
        return std::unexpected("token endpoint returned " +
                               std::to_string(result->status) + ": " +
                               result->body.substr(0, 500));
    }
    std::string response_body = result->body;
#endif

    // Zero credentials (secret was in the auth header, not the body, but wipe defensively)
    std::fill(credentials.begin(), credentials.end(), '\0');

    // Parse token response
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(response_body);
    } catch (const nlohmann::json::parse_error& e) {
        return std::unexpected(std::string("token response parse error: ") + e.what());
    }

    if (j.contains("error")) {
        auto err = j["error"].get<std::string>();
        auto desc = j.value("error_description", "");
        return std::unexpected("token error: " + err + " - " + desc);
    }

    if (!j.contains("access_token") || !j["access_token"].is_string()) {
        return std::unexpected("no access_token in token response");
    }

    spdlog::info("DirectorySync: acquired access token (expires_in={})",
                 j.value("expires_in", 0));
    return j["access_token"].get<std::string>();
}

// ── Entra ID sync ────────────────────────────────────────────────────────────

std::expected<void, std::string> DirectorySync::sync_entra(const EntraConfig& config) {
    if (config.tenant_id.empty() || config.client_id.empty() || config.client_secret.empty()) {
        return std::unexpected("Entra config incomplete: tenant_id, client_id, and client_secret required");
    }

    update_status("entra", "running");
    spdlog::info("DirectorySync: starting Entra ID sync for tenant {}", config.tenant_id);

    // 1. Acquire access token via client credentials flow
    auto token_result = acquire_token(config);
    if (!token_result) {
        auto err = "token acquisition failed: " + token_result.error();
        update_status("entra", "failed", 0, 0, err);
        spdlog::error("DirectorySync: {}", err);
        return std::unexpected(err);
    }
    auto& access_token = *token_result;

    // 2. Fetch users from Microsoft Graph
    int user_count = 0;
    {
        std::string users_url = "https://graph.microsoft.com/v1.0/users"
                                "?$select=id,displayName,mail,userPrincipalName,accountEnabled"
                                "&$top=999";

        auto users_result = http_get(users_url, access_token);
        if (!users_result) {
            auto err = "fetching users failed: " + users_result.error();
            update_status("entra", "failed", 0, 0, err);
            spdlog::error("DirectorySync: {}", err);
            return std::unexpected(err);
        }

        nlohmann::json users_json;
        try {
            users_json = nlohmann::json::parse(*users_result);
        } catch (const nlohmann::json::parse_error& e) {
            auto err = std::string("users response parse error: ") + e.what();
            update_status("entra", "failed", 0, 0, err);
            return std::unexpected(err);
        }

        if (!users_json.contains("value") || !users_json["value"].is_array()) {
            auto err = "unexpected Graph API response: no 'value' array";
            update_status("entra", "failed", 0, 0, err);
            return std::unexpected(err);
        }

        std::unique_lock lock(mtx_);
        for (const auto& u : users_json["value"]) {
            DirectoryUser du;
            du.id = u.value("id", "");
            du.display_name = u.value("displayName", "");
            du.email = u.value("mail", "");
            du.upn = u.value("userPrincipalName", "");
            du.enabled = u.value("accountEnabled", true);
            du.synced_at = now_epoch();

            if (!du.id.empty()) {
                store_user(du);
                ++user_count;
            }
        }
    }

    // 3. Fetch groups
    int group_count = 0;
    {
        std::string groups_url = "https://graph.microsoft.com/v1.0/groups"
                                 "?$select=id,displayName,description"
                                 "&$top=999";

        auto groups_result = http_get(groups_url, access_token);
        if (!groups_result) {
            auto err = "fetching groups failed: " + groups_result.error();
            update_status("entra", "failed", user_count, 0, err);
            spdlog::error("DirectorySync: {}", err);
            return std::unexpected(err);
        }

        nlohmann::json groups_json;
        try {
            groups_json = nlohmann::json::parse(*groups_result);
        } catch (const nlohmann::json::parse_error& e) {
            auto err = std::string("groups response parse error: ") + e.what();
            update_status("entra", "failed", user_count, 0, err);
            return std::unexpected(err);
        }

        if (groups_json.contains("value") && groups_json["value"].is_array()) {
            std::unique_lock lock(mtx_);
            // Clear old memberships before re-populating
            clear_memberships();

            for (const auto& g : groups_json["value"]) {
                DirectoryGroup dg;
                dg.id = g.value("id", "");
                dg.display_name = g.value("displayName", "");
                dg.description = g.value("description", "");
                dg.synced_at = now_epoch();

                // Preserve existing role mapping if any
                auto mappings = get_group_role_mappings();
                auto it = mappings.find(dg.id);
                if (it != mappings.end())
                    dg.mapped_role = it->second;

                if (!dg.id.empty()) {
                    store_group(dg);
                    ++group_count;
                }
            }
        }
    }

    // 4. Fetch group memberships
    {
        // Re-read groups to get their IDs
        auto groups = get_synced_groups();
        for (const auto& g : groups) {
            std::string members_url = "https://graph.microsoft.com/v1.0/groups/" +
                                      g.id + "/members?$select=id&$top=999";

            auto members_result = http_get(members_url, access_token);
            if (!members_result) {
                spdlog::warn("DirectorySync: failed to fetch members for group {}: {}",
                             g.display_name, members_result.error());
                continue;
            }

            nlohmann::json members_json;
            try {
                members_json = nlohmann::json::parse(*members_result);
            } catch (const nlohmann::json::parse_error&) {
                continue;
            }

            if (members_json.contains("value") && members_json["value"].is_array()) {
                std::unique_lock lock(mtx_);
                for (const auto& m : members_json["value"]) {
                    auto member_id = m.value("id", "");
                    if (!member_id.empty()) {
                        store_membership(member_id, g.id);
                    }
                }
            }
        }
    }

    update_status("entra", "completed", user_count, group_count);
    spdlog::info("DirectorySync: Entra sync completed — {} users, {} groups",
                 user_count, group_count);
    return {};
}

// ── LDAP sync (stub) ─────────────────────────────────────────────────────────

std::expected<void, std::string> DirectorySync::sync_ldap(const LdapConfig& /*config*/) {
    // LDAP support is planned but requires a dedicated LDAP library (e.g. ldap3,
    // OpenLDAP client) which is not currently in our vcpkg manifest. Entra ID
    // sync is available now and covers the majority of enterprise use cases.
    //
    // When LDAP support is added, this method will:
    // 1. Bind to the LDAP server (simple bind or SASL)
    // 2. Search for users under the configured base DN
    //    (objectClass=person, objectClass=user)
    // 3. Search for groups (objectClass=group, objectClass=groupOfNames)
    // 4. Resolve group memberships via member/memberOf attributes
    // 5. Store results in the same SQLite tables as Entra sync

    spdlog::info("DirectorySync: LDAP sync not yet implemented — use Entra ID");
    return std::unexpected(
        "LDAP sync is planned but not yet implemented. "
        "Entra ID (Azure AD) sync is available now via POST /api/directory/sync "
        "with provider='entra'. To enable LDAP support, add an LDAP client "
        "library to vcpkg.json and implement the bind/search flow.");
}

// ── Storage helpers ──────────────────────────────────────────────────────────

void DirectorySync::store_user(const DirectoryUser& user) {
    // Caller must hold lock
    if (!db_)
        return;

    const char* sql = R"(
        INSERT OR REPLACE INTO directory_users (id, display_name, email, upn, enabled, synced_at)
        VALUES (?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, user.id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user.display_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, user.email.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, user.upn.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, user.enabled ? 1 : 0);
    sqlite3_bind_int64(stmt, 6, user.synced_at);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void DirectorySync::store_group(const DirectoryGroup& group) {
    // Caller must hold lock
    if (!db_)
        return;

    const char* sql = R"(
        INSERT OR REPLACE INTO directory_groups (id, display_name, description, mapped_role, synced_at)
        VALUES (?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, group.id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, group.display_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, group.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, group.mapped_role.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, group.synced_at);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void DirectorySync::store_membership(const std::string& user_id, const std::string& group_id) {
    // Caller must hold lock
    if (!db_)
        return;

    const char* sql = "INSERT OR IGNORE INTO directory_memberships (user_id, group_id) VALUES (?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, group_id.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void DirectorySync::clear_memberships() {
    // Caller must hold lock
    if (!db_)
        return;
    sqlite3_exec(db_, "DELETE FROM directory_memberships;", nullptr, nullptr, nullptr);
}

void DirectorySync::update_status(const std::string& provider, const std::string& status,
                                  int user_count, int group_count,
                                  const std::string& error) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    const char* sql = R"(
        INSERT OR REPLACE INTO directory_sync_status
            (provider, status, last_sync_at, user_count, group_count, last_error)
        VALUES (?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, provider.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, now_epoch());
    sqlite3_bind_int(stmt, 4, user_count);
    sqlite3_bind_int(stmt, 5, group_count);
    sqlite3_bind_text(stmt, 6, error.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ── Query ────────────────────────────────────────────────────────────────────

std::vector<DirectoryUser> DirectorySync::get_synced_users(
    const std::string& group_filter) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return {};

    std::vector<DirectoryUser> result;
    sqlite3_stmt* stmt = nullptr;

    if (group_filter.empty()) {
        const char* sql = R"(
            SELECT id, display_name, email, upn, enabled, synced_at
            FROM directory_users ORDER BY display_name
        )";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return {};
    } else {
        const char* sql = R"(
            SELECT u.id, u.display_name, u.email, u.upn, u.enabled, u.synced_at
            FROM directory_users u
            JOIN directory_memberships m ON m.user_id = u.id
            WHERE m.group_id = ?
            ORDER BY u.display_name
        )";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return {};
        sqlite3_bind_text(stmt, 1, group_filter.c_str(), -1, SQLITE_TRANSIENT);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        DirectoryUser u;
        u.id = col_text(stmt, 0);
        u.display_name = col_text(stmt, 1);
        u.email = col_text(stmt, 2);
        u.upn = col_text(stmt, 3);
        u.enabled = sqlite3_column_int(stmt, 4) != 0;
        u.synced_at = sqlite3_column_int64(stmt, 5);

        // Load group memberships for this user
        sqlite3_stmt* gstmt = nullptr;
        const char* gsql = R"(
            SELECT g.display_name FROM directory_groups g
            JOIN directory_memberships m ON m.group_id = g.id
            WHERE m.user_id = ?
        )";
        if (sqlite3_prepare_v2(db_, gsql, -1, &gstmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(gstmt, 1, u.id.c_str(), -1, SQLITE_TRANSIENT);
            while (sqlite3_step(gstmt) == SQLITE_ROW)
                u.groups.push_back(col_text(gstmt, 0));
            sqlite3_finalize(gstmt);
        }

        result.push_back(std::move(u));
    }

    sqlite3_finalize(stmt);
    return result;
}

std::optional<DirectoryUser> DirectorySync::get_user(const std::string& id) const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return std::nullopt;

    const char* sql = R"(
        SELECT id, display_name, email, upn, enabled, synced_at
        FROM directory_users WHERE id = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    DirectoryUser u;
    u.id = col_text(stmt, 0);
    u.display_name = col_text(stmt, 1);
    u.email = col_text(stmt, 2);
    u.upn = col_text(stmt, 3);
    u.enabled = sqlite3_column_int(stmt, 4) != 0;
    u.synced_at = sqlite3_column_int64(stmt, 5);
    sqlite3_finalize(stmt);

    // Load groups
    sqlite3_stmt* gstmt = nullptr;
    const char* gsql = R"(
        SELECT g.display_name FROM directory_groups g
        JOIN directory_memberships m ON m.group_id = g.id
        WHERE m.user_id = ?
    )";
    if (sqlite3_prepare_v2(db_, gsql, -1, &gstmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(gstmt, 1, u.id.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(gstmt) == SQLITE_ROW)
            u.groups.push_back(col_text(gstmt, 0));
        sqlite3_finalize(gstmt);
    }

    return u;
}

std::vector<DirectoryGroup> DirectorySync::get_synced_groups() const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return {};

    const char* sql = R"(
        SELECT id, display_name, description, mapped_role, synced_at
        FROM directory_groups ORDER BY display_name
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return {};

    std::vector<DirectoryGroup> result;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        DirectoryGroup g;
        g.id = col_text(stmt, 0);
        g.display_name = col_text(stmt, 1);
        g.description = col_text(stmt, 2);
        g.mapped_role = col_text(stmt, 3);
        g.synced_at = sqlite3_column_int64(stmt, 4);
        result.push_back(std::move(g));
    }

    sqlite3_finalize(stmt);
    return result;
}

SyncStatus DirectorySync::get_status() const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return {};

    const char* sql = R"(
        SELECT provider, status, last_sync_at, next_sync_at, user_count, group_count, last_error
        FROM directory_sync_status WHERE provider = 'entra'
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return {};

    SyncStatus s;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        s.provider = col_text(stmt, 0);
        s.status = col_text(stmt, 1);
        s.last_sync_at = sqlite3_column_int64(stmt, 2);
        s.next_sync_at = sqlite3_column_int64(stmt, 3);
        s.user_count = sqlite3_column_int(stmt, 4);
        s.group_count = sqlite3_column_int(stmt, 5);
        s.last_error = col_text(stmt, 6);
    } else {
        s.provider = "entra";
        s.status = "idle";
    }

    sqlite3_finalize(stmt);
    return s;
}

// ── Group-to-role mapping ────────────────────────────────────────────────────

void DirectorySync::configure_group_role_mapping(const std::string& group_id,
                                                  const std::string& role_name) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    const char* sql = R"(
        INSERT OR REPLACE INTO directory_group_role_mappings (group_id, role_name)
        VALUES (?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, group_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, role_name.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // Also update the group record's mapped_role
    const char* update_sql = "UPDATE directory_groups SET mapped_role = ? WHERE id = ?";
    sqlite3_stmt* ustmt = nullptr;
    if (sqlite3_prepare_v2(db_, update_sql, -1, &ustmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(ustmt, 1, role_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ustmt, 2, group_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(ustmt);
        sqlite3_finalize(ustmt);
    }

    spdlog::info("DirectorySync: mapped group {} -> role '{}'", group_id, role_name);
}

void DirectorySync::remove_group_role_mapping(const std::string& group_id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    const char* sql = "DELETE FROM directory_group_role_mappings WHERE group_id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, group_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // Clear mapped_role on the group record
    const char* update_sql = "UPDATE directory_groups SET mapped_role = '' WHERE id = ?";
    sqlite3_stmt* ustmt = nullptr;
    if (sqlite3_prepare_v2(db_, update_sql, -1, &ustmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(ustmt, 1, group_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(ustmt);
        sqlite3_finalize(ustmt);
    }

    spdlog::info("DirectorySync: removed role mapping for group {}", group_id);
}

std::map<std::string, std::string> DirectorySync::get_group_role_mappings() const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return {};

    const char* sql = "SELECT group_id, role_name FROM directory_group_role_mappings";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return {};

    std::map<std::string, std::string> result;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        result[col_text(stmt, 0)] = col_text(stmt, 1);
    }

    sqlite3_finalize(stmt);
    return result;
}

} // namespace yuzu::server
