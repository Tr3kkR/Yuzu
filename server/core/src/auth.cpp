#include <yuzu/server/auth.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
#  include <windows.h>
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
#  include <shlobj.h>
#else
#  include <openssl/evp.h>
#  include <openssl/rand.h>
#endif

namespace yuzu::server::auth {

// ── Platform crypto ─────────────────────────────────────────────────────────

std::vector<uint8_t> AuthManager::random_bytes(std::size_t n) {
    std::vector<uint8_t> buf(n);
#ifdef _WIN32
    auto status = BCryptGenRandom(nullptr, buf.data(),
                                  static_cast<ULONG>(n),
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
        auto byte = static_cast<uint8_t>(
            std::stoul(hex.substr(i, 2), nullptr, 16));
        out.push_back(byte);
    }
    return out;
}

std::string AuthManager::pbkdf2_sha256(const std::string& password,
                                       const std::vector<uint8_t>& salt,
                                       int iterations) {
    constexpr int kKeyLen = 32;  // SHA-256 output
    std::vector<uint8_t> derived(kKeyLen);

#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    auto status = BCryptOpenAlgorithmProvider(&hAlg,
        BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");
    }

    status = BCryptDeriveKeyPBKDF2(
        hAlg,
        reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
        static_cast<ULONG>(password.size()),
        const_cast<PUCHAR>(salt.data()),
        static_cast<ULONG>(salt.size()),
        static_cast<ULONGLONG>(iterations),
        derived.data(),
        static_cast<ULONG>(derived.size()),
        0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptDeriveKeyPBKDF2 failed");
    }
#else
    if (!PKCS5_PBKDF2_HMAC(password.c_str(),
                            static_cast<int>(password.size()),
                            salt.data(),
                            static_cast<int>(salt.size()),
                            iterations, EVP_sha256(),
                            kKeyLen, derived.data())) {
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

// ── Config I/O ──────────────────────────────────────────────────────────────

bool AuthManager::load_config(const std::filesystem::path& cfg_path) {
    cfg_path_ = cfg_path;

    std::ifstream f(cfg_path);
    if (!f.is_open()) return false;

    std::lock_guard lock(mu_);
    users_.clear();

    std::string line;
    while (std::getline(f, line)) {
        // Trim
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty() || line[0] == '#') continue;

        // Format: username:role:salt_hex:hash_hex
        std::istringstream ss(line);
        std::string username, role_str, salt_hex, hash_hex;
        if (!std::getline(ss, username, ':')) continue;
        if (!std::getline(ss, role_str, ':')) continue;
        if (!std::getline(ss, salt_hex, ':')) continue;
        if (!std::getline(ss, hash_hex, ':')) continue;

        UserEntry entry;
        entry.username = username;
        entry.role     = string_to_role(role_str);
        entry.salt_hex = salt_hex;
        entry.hash_hex = hash_hex;
        users_[username] = std::move(entry);
    }

    spdlog::info("Loaded {} user(s) from {}", users_.size(), cfg_path.string());
    return !users_.empty();
}

bool AuthManager::save_config() const {
    std::lock_guard lock(mu_);

    auto parent = cfg_path_.parent_path();
    if (!parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            spdlog::error("Cannot create config directory {}: {}",
                          parent.string(), ec.message());
            return false;
        }
    }

    std::ofstream f(cfg_path_, std::ios::trunc);
    if (!f.is_open()) {
        spdlog::error("Cannot write config file {}", cfg_path_.string());
        return false;
    }

    f << "# Yuzu Server Configuration\n";
    f << "# Format: username:role:salt:hash\n";
    f << "# DO NOT EDIT — managed by yuzu-server\n\n";

    for (const auto& [name, entry] : users_) {
        f << entry.username << ':'
          << role_to_string(entry.role) << ':'
          << entry.salt_hex << ':'
          << entry.hash_hex << '\n';
    }

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

    if (input.empty() && !default_val.empty()) return default_val;
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
    if (admin_pw.empty()) {
        std::cerr << "Password cannot be empty.\n";
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
    if (user_pw.empty()) {
        std::cerr << "Password cannot be empty.\n";
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

std::optional<std::string> AuthManager::authenticate(
        const std::string& username, const std::string& password) {
    std::lock_guard lock(mu_);

    auto it = users_.find(username);
    if (it == users_.end()) {
        spdlog::warn("Auth failed: unknown user '{}'", username);
        return std::nullopt;
    }

    auto salt = hex_to_bytes(it->second.salt_hex);
    auto hash = pbkdf2_sha256(password, salt, kPbkdf2Iterations);

    if (hash != it->second.hash_hex) {
        spdlog::warn("Auth failed: bad password for '{}'", username);
        return std::nullopt;
    }

    auto token = generate_session_token();
    Session s;
    s.username   = username;
    s.role       = it->second.role;
    s.expires_at = std::chrono::steady_clock::now() + kSessionDuration;
    sessions_[token] = std::move(s);

    spdlog::info("User '{}' authenticated (role={})", username,
                 role_to_string(it->second.role));
    return token;
}

std::optional<Session> AuthManager::validate_session(
        const std::string& token) const {
    std::lock_guard lock(mu_);

    auto it = sessions_.find(token);
    if (it == sessions_.end()) return std::nullopt;

    if (std::chrono::steady_clock::now() > it->second.expires_at) {
        sessions_.erase(it);
        return std::nullopt;
    }

    return it->second;
}

void AuthManager::invalidate_session(const std::string& token) {
    std::lock_guard lock(mu_);
    sessions_.erase(token);
}

// ── User management ─────────────────────────────────────────────────────────

bool AuthManager::has_users() const {
    std::lock_guard lock(mu_);
    return !users_.empty();
}

std::vector<UserEntry> AuthManager::list_users() const {
    std::lock_guard lock(mu_);
    std::vector<UserEntry> out;
    out.reserve(users_.size());
    for (const auto& [_, e] : users_) {
        out.push_back(e);
    }
    return out;
}

bool AuthManager::upsert_user(const std::string& username,
                              const std::string& password, Role role) {
    auto salt = random_bytes(16);
    auto hash = pbkdf2_sha256(password, salt, kPbkdf2Iterations);

    std::lock_guard lock(mu_);
    UserEntry entry;
    entry.username = username;
    entry.role     = role;
    entry.salt_hex = bytes_to_hex(salt);
    entry.hash_hex = hash;
    users_[username] = std::move(entry);
    return true;
}

bool AuthManager::remove_user(const std::string& username) {
    std::lock_guard lock(mu_);
    return users_.erase(username) > 0;
}

}  // namespace yuzu::server::auth
