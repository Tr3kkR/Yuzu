#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server::auth {

enum class Role { user, admin };

struct UserEntry {
    std::string username;
    Role        role;
    std::string salt_hex;
    std::string hash_hex;
};

struct Session {
    std::string username;
    Role        role;
    std::chrono::steady_clock::time_point expires_at;
};

class AuthManager {
public:
    static constexpr auto kSessionDuration = std::chrono::hours(8);
    static constexpr int  kPbkdf2Iterations = 100'000;

    /// Load users from config file. Returns false if file missing/corrupt.
    bool load_config(const std::filesystem::path& cfg_path);

    /// Persist current user list to disk.
    bool save_config() const;

    /// Interactive first-run: prompt for admin + user credentials, write config.
    static bool first_run_setup(const std::filesystem::path& cfg_path);

    /// Authenticate; returns session token on success.
    std::optional<std::string> authenticate(const std::string& username,
                                            const std::string& password);

    /// Look up a session by cookie token.
    std::optional<Session> validate_session(const std::string& token) const;

    /// Destroy a session (logout).
    void invalidate_session(const std::string& token);

    /// List all configured users (password hashes omitted from caller view).
    std::vector<UserEntry> list_users() const;

    /// Add or overwrite a user.
    bool upsert_user(const std::string& username,
                     const std::string& password, Role role);

    /// Remove a user by name.
    bool remove_user(const std::string& username);

    /// Check whether any users are configured.
    bool has_users() const;

    const std::filesystem::path& config_path() const { return cfg_path_; }

    // -- Crypto primitives (platform-abstracted) --------------------------

    static std::vector<uint8_t> random_bytes(std::size_t n);
    static std::string          bytes_to_hex(const std::vector<uint8_t>& v);
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
    static std::string          pbkdf2_sha256(const std::string& password,
                                              const std::vector<uint8_t>& salt,
                                              int iterations);

private:
    static std::string generate_session_token();

    mutable std::mutex mu_;
    std::filesystem::path cfg_path_;
    std::unordered_map<std::string, UserEntry> users_;
    mutable std::unordered_map<std::string, Session> sessions_;
};

// OS-appropriate default paths.
std::filesystem::path default_config_path();
std::filesystem::path default_cert_dir();

std::string role_to_string(Role r);
Role        string_to_role(const std::string& s);

}  // namespace yuzu::server::auth
