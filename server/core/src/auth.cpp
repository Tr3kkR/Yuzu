#include <yuzu/server/auth.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
// clang-format off
#include <windows.h>  // must precede bcrypt.h (provides NTSTATUS)
#include <bcrypt.h>
// clang-format on
#pragma comment(lib, "bcrypt.lib")
#include <shlobj.h>
#else
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/stat.h>  // umask()
#endif

namespace yuzu::server::auth {

// ── Platform crypto ─────────────────────────────────────────────────────────

std::vector<uint8_t> AuthManager::random_bytes(std::size_t n) {
    std::vector<uint8_t> buf(n);
#ifdef _WIN32
    auto status = BCryptGenRandom(nullptr, buf.data(), static_cast<ULONG>(n),
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptGenRandom failed");
    }
#else
    if (RAND_bytes(buf.data(), static_cast<int>(n)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
#endif
    return buf;
}

std::string AuthManager::bytes_to_hex(const std::vector<uint8_t>& v) {
    std::string out;
    out.reserve(v.size() * 2);
    for (auto b : v) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", b);
        out.append(buf, 2);
    }
    return out;
}

std::vector<uint8_t> AuthManager::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        auto byte = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
        out.push_back(byte);
    }
    return out;
}

std::string AuthManager::pbkdf2_sha256(const std::string& password,
                                       const std::vector<uint8_t>& salt, int iterations) {
    constexpr int kKeyLen = 32; // SHA-256 output
    std::vector<uint8_t> derived(kKeyLen);

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    auto status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                              BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
    }

    status =
        BCryptDeriveKeyPBKDF2(hAlg, reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
                              static_cast<ULONG>(password.size()), const_cast<PUCHAR>(salt.data()),
                              static_cast<ULONG>(salt.size()), static_cast<ULONGLONG>(iterations),
                              derived.data(), static_cast<ULONG>(derived.size()), 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptDeriveKeyPBKDF2 failed");
    }
#else
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()), salt.data(),
                           static_cast<int>(salt.size()), iterations, EVP_sha256(), kKeyLen,
                           derived.data())) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
    }
#endif

    return bytes_to_hex(derived);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

std::string role_to_string(Role r) {
    return r == Role::admin ? "admin" : "user";
}

Role string_to_role(const std::string& s) {
    return s == "admin" ? Role::admin : Role::user;
}

std::filesystem::path default_config_path() {
#ifdef _WIN32
    return R"(C:\ProgramData\Yuzu\yuzu-server.cfg)";
#elif defined(__APPLE__)
    // Use per-user Application Support when not running as root
    if (const char* home = std::getenv("HOME")) {
        return std::filesystem::path(home) / "Library/Application Support/Yuzu/yuzu-server.cfg";
    }
    return "/Library/Application Support/Yuzu/yuzu-server.cfg";
#else
    return "/etc/yuzu/yuzu-server.cfg";
#endif
}

std::filesystem::path default_cert_dir() {
#ifdef _WIN32
    return R"(C:\ProgramData\Yuzu\certs)";
#elif defined(__APPLE__)
    return "/etc/yuzu/certs";
#else
    return "/etc/yuzu/certs";
#endif
}

std::string AuthManager::generate_session_token() {
    return bytes_to_hex(random_bytes(32));
}

bool AuthManager::constant_time_compare(const std::string& a, const std::string& b) {
    if (a.size() != b.size())
        return false;
    volatile unsigned char result = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        result |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return result == 0;
}

// ── Config I/O ──────────────────────────────────────────────────────────────

bool AuthManager::load_config(const std::filesystem::path& cfg_path) {
    cfg_path_ = cfg_path;

    std::ifstream f(cfg_path);
    if (!f.is_open())
        return false;

    bool has_users = false;
    {
        std::unique_lock lock(mu_);
        users_.clear();

        std::string line;
        while (std::getline(f, line)) {
            // Trim
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            if (line.empty())
                continue;
            // Parse version header (e.g. "# Version: 1")
            if (line.starts_with("# Version: ")) {
                try {
                    int ver = std::stoi(line.substr(11));
                    if (ver != 1) {
                        spdlog::error("Unsupported config file version {} in {}", ver, cfg_path.string());
                        return false;
                    }
                } catch (const std::exception& e) {
                    spdlog::error("Malformed version line in {}: {}", cfg_path.string(), e.what());
                    return false;
                }
                continue;
            }
            if (line[0] == '#')
                continue;

            // Format: username:role:salt_hex:hash_hex
            std::istringstream ss(line);
            std::string username, role_str, salt_hex, hash_hex;
            if (!std::getline(ss, username, ':'))
                continue;
            if (!std::getline(ss, role_str, ':'))
                continue;
            if (!std::getline(ss, salt_hex, ':'))
                continue;
            if (!std::getline(ss, hash_hex, ':'))
                continue;

            UserEntry entry;
            entry.username = username;
            entry.role = string_to_role(role_str);
            entry.salt_hex = salt_hex;
            entry.hash_hex = hash_hex;
            users_[username] = std::move(entry);
        }

        has_users = !users_.empty();
        spdlog::info("Loaded {} user(s) from {}", users_.size(), cfg_path.string());
    }

    // Load enrollment tokens and pending agents (each acquires mu_ internally)
    load_tokens();
    load_pending();

    return has_users;
}

bool AuthManager::save_config() const {
    std::shared_lock lock(mu_);

    auto parent = cfg_path_.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            spdlog::error("Cannot create config directory {}: {}", parent.string(), ec.message());
            return false;
        }
    }

#ifndef _WIN32
    // Set restrictive umask so the file is created with 0600 from the start,
    // closing the TOCTOU window where it could be world-readable.
    mode_t old_mask = umask(0077);
#endif
    std::ofstream f(cfg_path_, std::ios::trunc);
#ifndef _WIN32
    umask(old_mask);
#endif
    if (!f.is_open()) {
        spdlog::error("Cannot write config file {}", cfg_path_.string());
        return false;
    }

    f << "# Yuzu Server Configuration\n";
    f << "# Version: 1\n";
    f << "# Format: username:role:salt:hash\n";
    f << "# DO NOT EDIT — managed by yuzu-server\n\n";

    for (const auto& [name, entry] : users_) {
        f << entry.username << ':' << role_to_string(entry.role) << ':' << entry.salt_hex << ':'
          << entry.hash_hex << '\n';
    }
    f.close();

#ifndef _WIN32
    // Belt-and-suspenders: ensure 0600 even if the file pre-existed with looser perms.
    std::error_code perm_ec;
    std::filesystem::permissions(cfg_path_,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, perm_ec);
    if (perm_ec) {
        spdlog::warn("Failed to set permissions on {}: {}", cfg_path_.string(), perm_ec.message());
    }
#endif

    spdlog::info("Saved {} user(s) to {}", users_.size(), cfg_path_.string());
    return true;
}

// ── First-run setup ─────────────────────────────────────────────────────────

static std::string prompt(const std::string& msg, const std::string& default_val = {}) {
    if (default_val.empty()) {
        std::cout << msg << ": ";
    } else {
        std::cout << msg << " [" << default_val << "]: ";
    }
    std::cout.flush();

    std::string input;
    std::getline(std::cin, input);
    // Trim
    while (!input.empty() && (input.back() == '\r' || input.back() == '\n'))
        input.pop_back();

    if (input.empty() && !default_val.empty())
        return default_val;
    return input;
}

static std::string prompt_password(const std::string& msg) {
    std::cout << msg << ": ";
    std::cout.flush();

    // Disable echo
#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);
#else
    // POSIX: use termios to disable echo
    struct termios_guard {
        // Simple approach: just read without echo toggle for now.
        // Full implementation would use tcgetattr/tcsetattr.
    };
#endif

    std::string pw;
    std::getline(std::cin, pw);
    while (!pw.empty() && (pw.back() == '\r' || pw.back() == '\n'))
        pw.pop_back();

    std::cout << '\n';

#ifdef _WIN32
    SetConsoleMode(hStdin, mode);
#endif

    return pw;
}

bool AuthManager::first_run_setup(const std::filesystem::path& cfg_path) {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════╗\n";
    std::cout << "║       Yuzu Server — First Run Setup      ║\n";
    std::cout << "╠══════════════════════════════════════════╣\n";
    std::cout << "║  No configuration file found.            ║\n";
    std::cout << "║  Let's create your initial accounts.     ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n\n";

    // Admin account
    auto admin_name = prompt("Admin account name", "admin");
    if (admin_name.empty()) {
        std::cerr << "Account name cannot be empty.\n";
        return false;
    }
    auto admin_pw = prompt_password("Admin password");
    if (admin_pw.size() < 12) {
        std::cerr << "Password must be at least 12 characters.\n";
        return false;
    }
    auto admin_pw2 = prompt_password("Confirm admin password");
    if (admin_pw != admin_pw2) {
        std::cerr << "Passwords do not match.\n";
        return false;
    }

    std::cout << '\n';

    // User account
    auto user_name = prompt("User account name", "user");
    if (user_name.empty()) {
        std::cerr << "Account name cannot be empty.\n";
        return false;
    }
    if (user_name == admin_name) {
        std::cerr << "User account must differ from admin account.\n";
        return false;
    }
    auto user_pw = prompt_password("User password");
    if (user_pw.size() < 12) {
        std::cerr << "Password must be at least 12 characters.\n";
        return false;
    }
    auto user_pw2 = prompt_password("Confirm user password");
    if (user_pw != user_pw2) {
        std::cerr << "Passwords do not match.\n";
        return false;
    }

    // Build and save config
    AuthManager mgr;
    mgr.cfg_path_ = cfg_path;
    mgr.upsert_user(admin_name, admin_pw, Role::admin);
    mgr.upsert_user(user_name, user_pw, Role::user);

    if (!mgr.save_config()) {
        std::cerr << "Failed to write config to " << cfg_path.string() << '\n';
        return false;
    }

    std::cout << "\nConfiguration saved to " << cfg_path.string() << '\n';
    std::cout << "You can now restart the server.\n\n";
    return true;
}

// ── Authentication ──────────────────────────────────────────────────────────

std::optional<std::string> AuthManager::authenticate(const std::string& username,
                                                     const std::string& password) {
    std::unique_lock lock(mu_);

    auto it = users_.find(username);
    if (it == users_.end()) {
        spdlog::warn("Auth failed: unknown user '{}'", username);
        return std::nullopt;
    }

    auto salt = hex_to_bytes(it->second.salt_hex);
    auto hash = pbkdf2_sha256(password, salt, kPbkdf2Iterations);

    if (!constant_time_compare(hash, it->second.hash_hex)) {
        spdlog::warn("Auth failed: bad password for '{}'", username);
        return std::nullopt;
    }

    auto token = generate_session_token();
    Session s;
    s.username = username;
    s.role = it->second.role;
    s.expires_at = std::chrono::steady_clock::now() + kSessionDuration;
    s.auth_source = "local";
    sessions_[token] = std::move(s);

    spdlog::info("User '{}' authenticated (role={})", username, role_to_string(it->second.role));
    return token;
}

std::optional<Session> AuthManager::validate_session(const std::string& token) const {
    // Reject overly-long tokens early to prevent DoS via map key exhaustion (#630).
    // This check intentionally fires BEFORE the mutex acquire below — rejecting
    // obviously invalid tokens without contention reduces lock contention under
    // token-spray attacks.
    if (token.size() > auth::kMaxSessionTokenLength)
        return std::nullopt;

    std::shared_lock lock(mu_);

    auto it = sessions_.find(token);
    if (it == sessions_.end())
        return std::nullopt;

    auto now = std::chrono::steady_clock::now();
    if (now > it->second.expires_at)
        return std::nullopt;

    // Opportunistic reap: if sessions exceed threshold, upgrade lock and sweep (G2-SEC-A1-004).
    // Copy the session BEFORE any lock manipulation to avoid dangling iterator after erase_if.
    auto session_copy = it->second;
    if (sessions_.size() > 100) {
        lock.unlock();
        std::unique_lock wlock(mu_);
        auto reap_now = std::chrono::steady_clock::now();
        std::erase_if(sessions_, [&](const auto& p) { return reap_now > p.second.expires_at; });
    }

    return session_copy;
}

void AuthManager::invalidate_session(const std::string& token) {
    std::unique_lock lock(mu_);
    sessions_.erase(token);
}

// ── User management ─────────────────────────────────────────────────────────

bool AuthManager::has_users() const {
    std::shared_lock lock(mu_);
    return !users_.empty();
}

std::vector<UserEntry> AuthManager::list_users() const {
    std::shared_lock lock(mu_);
    std::vector<UserEntry> out;
    out.reserve(users_.size());
    for (const auto& [_, e] : users_) {
        out.push_back(e);
    }
    return out;
}

bool AuthManager::upsert_user(const std::string& username, const std::string& password, Role role) {
    if (password.size() < 12)
        return false; // minimum password length (G2-SEC-A1-003)
    auto salt = random_bytes(16);
    auto hash = pbkdf2_sha256(password, salt, kPbkdf2Iterations);

    std::unique_lock lock(mu_);
    // Check if role is changing for an existing user
    auto it = users_.find(username);
    bool role_changed = it != users_.end() && it->second.role != role;

    UserEntry entry;
    entry.username = username;
    entry.role = role;
    entry.salt_hex = bytes_to_hex(salt);
    entry.hash_hex = hash;
    users_[username] = std::move(entry);

    if (role_changed) {
        // Invalidate sessions so the user picks up the new role on next login
        // Prevents stale session role from granting old privileges (G4-CON-AUTH-001)
        std::erase_if(sessions_, [&](const auto& pair) {
            return pair.second.username == username;
        });
    }
    return true;
}

bool AuthManager::remove_user(const std::string& username) {
    std::unique_lock lock(mu_);
    auto erased = users_.erase(username) > 0;
    if (erased) {
        // Invalidate all active sessions belonging to this user
        // to prevent deleted users from retaining access (CHAOS-T1-001)
        std::erase_if(sessions_, [&](const auto& pair) {
            return pair.second.username == username;
        });
    }
    return erased;
}

std::optional<Role> AuthManager::get_user_role(const std::string& username) const {
    std::shared_lock lock(mu_);
    auto it = users_.find(username);
    if (it == users_.end())
        return std::nullopt;
    return it->second.role;
}

// ── OIDC session creation ───────────────────────────────────────────────────

std::string AuthManager::create_oidc_session(const std::string& display_name,
                                             const std::string& email, const std::string& oidc_sub,
                                             const std::vector<std::string>& groups,
                                             const std::string& admin_group_id) {
    std::unique_lock lock(mu_);

    // Determine role: admin if user is in the configured admin group,
    // or if email/display_name matches a local admin account
    Role role = Role::user;
    if (!admin_group_id.empty()) {
        for (const auto& gid : groups) {
            if (gid == admin_group_id) {
                role = Role::admin;
                break;
            }
        }
    }
    if (role != Role::admin) {
        for (const auto& [name, entry] : users_) {
            if (entry.role == Role::admin && (name == email || name == display_name)) {
                role = Role::admin;
                break;
            }
        }
    }

    auto token = generate_session_token();
    Session s;
    s.username = display_name.empty() ? email : display_name;
    s.role = role;
    s.expires_at = std::chrono::steady_clock::now() + kSessionDuration;
    s.auth_source = "oidc";
    s.oidc_sub = oidc_sub;
    sessions_[token] = std::move(s);

    spdlog::info("OIDC session created for '{}' (email={}, sub={}, role={})",
                 display_name.empty() ? email : display_name, email, oidc_sub,
                 role_to_string(role));
    return token;
}

// ── Enrollment tokens (Tier 2) ──────────────────────────────────────────────

std::string AuthManager::sha256_hex(const std::string& input) {
    // Reuse PBKDF2 with 1 iteration and empty salt for a simple SHA-256 hash.
    // This is fine for token hashing (tokens are already high-entropy).
    constexpr int kKeyLen = 32;
    std::vector<uint8_t> derived(kKeyLen);

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    auto status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed for SHA-256");
    }

    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptCreateHash failed");
    }

    status = BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                            static_cast<ULONG>(input.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        throw std::runtime_error("BCryptHashData failed");
    }

    status = BCryptFinishHash(hHash, derived.data(), static_cast<ULONG>(derived.size()), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptFinishHash failed");
    }
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, derived.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP SHA-256 digest failed");
    }
    EVP_MD_CTX_free(ctx);
#endif

    return bytes_to_hex(derived);
}

std::string AuthManager::create_enrollment_token(const std::string& label, int max_uses,
                                                 std::chrono::seconds ttl) {
    // Generate a high-entropy raw token
    auto raw_bytes = random_bytes(32);
    auto raw_token = bytes_to_hex(raw_bytes);

    // Hash it for storage (we never store the raw token)
    auto hash = sha256_hex(raw_token);

    // Token ID = first 8 hex chars of the hash (for display/admin reference)
    auto token_id = hash.substr(0, 8);

    auto now = std::chrono::system_clock::now();

    EnrollmentToken et;
    et.token_id = token_id;
    et.token_hash = hash;
    et.label = label;
    et.max_uses = max_uses;
    et.use_count = 0;
    et.created_at = now;
    et.expires_at = (ttl.count() == 0) ? (std::chrono::system_clock::time_point::max)() : now + ttl;
    et.revoked = false;

    {
        std::unique_lock lock(mu_);
        enrollment_tokens_[token_id] = std::move(et);
    }

    save_tokens();

    spdlog::info("Enrollment token created: id={}, label='{}', max_uses={}, ttl={}s", token_id,
                 label, max_uses, ttl.count());
    return raw_token;
}

std::vector<std::string>
AuthManager::create_enrollment_tokens_batch(const std::string& label_prefix, int count,
                                            int max_uses_each, std::chrono::seconds ttl) {
    std::vector<std::string> tokens;
    tokens.reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; ++i) {
        auto label = label_prefix.empty() ? std::format("batch-{}", i + 1)
                                          : std::format("{}-{}", label_prefix, i + 1);
        tokens.push_back(create_enrollment_token(label, max_uses_each, ttl));
    }
    spdlog::info("Batch created {} enrollment tokens (prefix='{}')", count, label_prefix);
    return tokens;
}

bool AuthManager::validate_enrollment_token(const std::string& raw_token) {
    auto hash = sha256_hex(raw_token);
    auto now = std::chrono::system_clock::now();

    std::unique_lock lock(mu_);

    for (auto& [id, et] : enrollment_tokens_) {
        if (!constant_time_compare(et.token_hash, hash))
            continue;

        if (et.revoked) {
            spdlog::warn("Enrollment token {} is revoked", id);
            return false;
        }
        if (now > et.expires_at) {
            spdlog::warn("Enrollment token {} has expired", id);
            return false;
        }
        if (et.max_uses > 0 && et.use_count >= et.max_uses) {
            spdlog::warn("Enrollment token {} exhausted ({}/{})", id, et.use_count, et.max_uses);
            return false;
        }

        ++et.use_count;
        spdlog::info("Enrollment token {} used ({}/{})", id, et.use_count,
                     et.max_uses == 0 ? -1 : et.max_uses);
        // Save updated use count (don't hold lock during file I/O — already locked)
        // We'll save after releasing; use a flag.
        return true;
    }

    spdlog::warn("Enrollment token not found (hash prefix={})", hash.substr(0, 8));
    return false;
}

std::vector<EnrollmentToken> AuthManager::list_enrollment_tokens() const {
    std::shared_lock lock(mu_);
    std::vector<EnrollmentToken> out;
    out.reserve(enrollment_tokens_.size());
    for (const auto& [_, et] : enrollment_tokens_) {
        out.push_back(et);
    }
    return out;
}

bool AuthManager::revoke_enrollment_token(const std::string& token_id) {
    {
        std::unique_lock lock(mu_);
        auto it = enrollment_tokens_.find(token_id);
        if (it == enrollment_tokens_.end())
            return false;
        it->second.revoked = true;
    }
    save_tokens();
    spdlog::info("Enrollment token {} revoked", token_id);
    return true;
}

// ── Enrollment token persistence ────────────────────────────────────────────

bool AuthManager::save_tokens() const {
    auto path = state_dir() / "enrollment-tokens.cfg";

    std::shared_lock lock(mu_);

#ifndef _WIN32
    mode_t old_mask = umask(0077);
#endif
    std::ofstream f(path, std::ios::trunc);
#ifndef _WIN32
    umask(old_mask);
#endif
    if (!f.is_open()) {
        spdlog::error("Cannot write enrollment tokens to {}", path.string());
        return false;
    }

    f << "# Yuzu Enrollment Tokens\n";
    f << "# Version: 1\n";
    f << "# Format: "
         "token_id:token_hash:label:max_uses:use_count:created_epoch:expires_epoch:revoked\n\n";

    for (const auto& [id, et] : enrollment_tokens_) {
        auto created_epoch =
            std::chrono::duration_cast<std::chrono::seconds>(et.created_at.time_since_epoch())
                .count();
        auto expires_epoch =
            (et.expires_at == (std::chrono::system_clock::time_point::max)())
                ? int64_t{0}
                : std::chrono::duration_cast<std::chrono::seconds>(et.expires_at.time_since_epoch())
                      .count();

        f << et.token_id << ':' << et.token_hash << ':' << et.label << ':' << et.max_uses << ':'
          << et.use_count << ':' << created_epoch << ':' << expires_epoch << ':'
          << (et.revoked ? '1' : '0') << '\n';
    }
    f.close();

#ifndef _WIN32
    // Restrict token file to owner-only (0600) — contains token hashes.
    std::error_code perm_ec;
    std::filesystem::permissions(path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, perm_ec);
    if (perm_ec) {
        spdlog::warn("Failed to set permissions on {}: {}", path.string(), perm_ec.message());
    }
#endif

    return true;
}

bool AuthManager::load_tokens() {
    auto path = state_dir() / "enrollment-tokens.cfg";

    std::ifstream f(path);
    if (!f.is_open())
        return false;

    std::unique_lock lock(mu_);
    enrollment_tokens_.clear();

    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty())
            continue;
        if (line.starts_with("# Version: ")) {
            try {
                int ver = std::stoi(line.substr(11));
                if (ver != 1) {
                    spdlog::error("Unsupported enrollment-tokens.cfg version {}", ver);
                    return false;
                }
            } catch (const std::exception& e) {
                spdlog::error("Malformed version line in enrollment-tokens.cfg: {}", e.what());
                return false;
            }
            continue;
        }
        if (line[0] == '#')
            continue;

        std::istringstream ss(line);
        std::string token_id, token_hash, label, max_uses_s, use_count_s, created_s, expires_s,
            revoked_s;

        if (!std::getline(ss, token_id, ':'))
            continue;
        if (!std::getline(ss, token_hash, ':'))
            continue;
        if (!std::getline(ss, label, ':'))
            continue;
        if (!std::getline(ss, max_uses_s, ':'))
            continue;
        if (!std::getline(ss, use_count_s, ':'))
            continue;
        if (!std::getline(ss, created_s, ':'))
            continue;
        if (!std::getline(ss, expires_s, ':'))
            continue;
        if (!std::getline(ss, revoked_s, ':'))
            continue;

        EnrollmentToken et;
        et.token_id = token_id;
        et.token_hash = token_hash;
        et.label = label;
        et.max_uses = std::stoi(max_uses_s);
        et.use_count = std::stoi(use_count_s);
        et.created_at =
            std::chrono::system_clock::time_point(std::chrono::seconds(std::stoll(created_s)));
        et.expires_at = (expires_s == "0") ? (std::chrono::system_clock::time_point::max)()
                                           : std::chrono::system_clock::time_point(
                                                 std::chrono::seconds(std::stoll(expires_s)));
        et.revoked = (revoked_s == "1");

        enrollment_tokens_[token_id] = std::move(et);
    }

    spdlog::info("Loaded {} enrollment token(s)", enrollment_tokens_.size());
    return true;
}

// ── Pending agents (Tier 1) ─────────────────────────────────────────────────

std::string pending_status_to_string(PendingStatus s) {
    switch (s) {
    case PendingStatus::pending:
        return "pending";
    case PendingStatus::approved:
        return "approved";
    case PendingStatus::denied:
        return "denied";
    }
    return "unknown";
}

void AuthManager::add_pending_agent(const std::string& agent_id, const std::string& hostname,
                                    const std::string& os, const std::string& arch,
                                    const std::string& agent_version) {
    {
        std::unique_lock lock(mu_);
        // Don't overwrite if already exists
        if (pending_agents_.contains(agent_id))
            return;

        PendingAgent pa;
        pa.agent_id = agent_id;
        pa.hostname = hostname;
        pa.os = os;
        pa.arch = arch;
        pa.agent_version = agent_version;
        pa.requested_at = std::chrono::system_clock::now();
        pa.status = PendingStatus::pending;
        pending_agents_[agent_id] = std::move(pa);
    }
    save_pending();
    spdlog::info("Agent {} added to pending approval queue", agent_id);
}

std::optional<PendingStatus> AuthManager::get_pending_status(const std::string& agent_id) const {
    std::shared_lock lock(mu_);
    auto it = pending_agents_.find(agent_id);
    if (it == pending_agents_.end())
        return std::nullopt;
    return it->second.status;
}

std::vector<PendingAgent> AuthManager::list_pending_agents() const {
    std::shared_lock lock(mu_);
    std::vector<PendingAgent> out;
    out.reserve(pending_agents_.size());
    for (const auto& [_, pa] : pending_agents_) {
        out.push_back(pa);
    }
    return out;
}

bool AuthManager::approve_pending_agent(const std::string& agent_id) {
    {
        std::unique_lock lock(mu_);
        auto it = pending_agents_.find(agent_id);
        if (it == pending_agents_.end())
            return false;
        it->second.status = PendingStatus::approved;
    }
    save_pending();
    spdlog::info("Agent {} approved for enrollment", agent_id);
    return true;
}

bool AuthManager::deny_pending_agent(const std::string& agent_id) {
    {
        std::unique_lock lock(mu_);
        auto it = pending_agents_.find(agent_id);
        if (it == pending_agents_.end())
            return false;
        it->second.status = PendingStatus::denied;
    }
    save_pending();
    spdlog::info("Agent {} denied enrollment", agent_id);
    return true;
}

bool AuthManager::ensure_enrolled(const std::string& agent_id, const std::string& hostname,
                                  const std::string& os, const std::string& arch,
                                  const std::string& agent_version) {
    {
        std::unique_lock lock(mu_);
        auto it = pending_agents_.find(agent_id);
        if (it != pending_agents_.end()) {
            // Never override an explicit admin denial — tokens don't outrank admins
            if (it->second.status == PendingStatus::denied) {
                spdlog::warn("ensure_enrolled: agent {} is admin-denied, refusing to override",
                             agent_id);
                return false;
            }
            it->second.status = PendingStatus::approved;
        } else {
            PendingAgent pa;
            pa.agent_id = agent_id;
            pa.hostname = hostname;
            pa.os = os;
            pa.arch = arch;
            pa.agent_version = agent_version;
            pa.requested_at = std::chrono::system_clock::now();
            pa.status = PendingStatus::approved;
            pending_agents_[agent_id] = std::move(pa);
        }
    }
    save_pending();
    return true;
}

bool AuthManager::remove_pending_agent(const std::string& agent_id) {
    {
        std::unique_lock lock(mu_);
        if (pending_agents_.erase(agent_id) == 0)
            return false;
    }
    save_pending();
    return true;
}

// ── Pending agent persistence ───────────────────────────────────────────────

bool AuthManager::save_pending() const {
    auto path = state_dir() / "pending-agents.cfg";

    std::shared_lock lock(mu_);

#ifndef _WIN32
    mode_t old_mask = umask(0077);
#endif
    std::ofstream f(path, std::ios::trunc);
#ifndef _WIN32
    umask(old_mask);
#endif
    if (!f.is_open()) {
        spdlog::error("Cannot write pending agents to {}", path.string());
        return false;
    }

    f << "# Yuzu Pending Agents\n";
    f << "# Version: 1\n";
    f << "# Format: agent_id:hostname:os:arch:version:requested_epoch:status\n\n";

    for (const auto& [id, pa] : pending_agents_) {
        auto epoch =
            std::chrono::duration_cast<std::chrono::seconds>(pa.requested_at.time_since_epoch())
                .count();

        f << pa.agent_id << ':' << pa.hostname << ':' << pa.os << ':' << pa.arch << ':'
          << pa.agent_version << ':' << epoch << ':' << pending_status_to_string(pa.status) << '\n';
    }
    f.close();

#ifndef _WIN32
    // Restrict pending-agents file to owner-only (0600).
    std::error_code perm_ec;
    std::filesystem::permissions(path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, perm_ec);
    if (perm_ec) {
        spdlog::warn("Failed to set permissions on {}: {}", path.string(), perm_ec.message());
    }
#endif

    return true;
}

bool AuthManager::load_pending() {
    auto path = state_dir() / "pending-agents.cfg";

    std::ifstream f(path);
    if (!f.is_open())
        return false;

    std::unique_lock lock(mu_);
    pending_agents_.clear();

    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty())
            continue;
        if (line.starts_with("# Version: ")) {
            try {
                int ver = std::stoi(line.substr(11));
                if (ver != 1) {
                    spdlog::error("Unsupported pending-agents.cfg version {}", ver);
                    return false;
                }
            } catch (const std::exception& e) {
                spdlog::error("Malformed version line in pending-agents.cfg: {}", e.what());
                return false;
            }
            continue;
        }
        if (line[0] == '#')
            continue;

        std::istringstream ss(line);
        std::string agent_id, hostname, os, arch, version, epoch_s, status_s;

        if (!std::getline(ss, agent_id, ':'))
            continue;
        if (!std::getline(ss, hostname, ':'))
            continue;
        if (!std::getline(ss, os, ':'))
            continue;
        if (!std::getline(ss, arch, ':'))
            continue;
        if (!std::getline(ss, version, ':'))
            continue;
        if (!std::getline(ss, epoch_s, ':'))
            continue;
        if (!std::getline(ss, status_s, ':'))
            continue;

        PendingAgent pa;
        pa.agent_id = agent_id;
        pa.hostname = hostname;
        pa.os = os;
        pa.arch = arch;
        pa.agent_version = version;
        pa.requested_at =
            std::chrono::system_clock::time_point(std::chrono::seconds(std::stoll(epoch_s)));

        if (status_s == "approved")
            pa.status = PendingStatus::approved;
        else if (status_s == "denied")
            pa.status = PendingStatus::denied;
        else
            pa.status = PendingStatus::pending;

        pending_agents_[agent_id] = std::move(pa);
    }

    spdlog::info("Loaded {} pending agent(s)", pending_agents_.size());
    return true;
}

} // namespace yuzu::server::auth
