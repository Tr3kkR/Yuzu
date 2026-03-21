#pragma once

#include <sqlite3.h>

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <map>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu::server {

// ── Data types ───────────────────────────────────────────────────────────────

struct DirectoryUser {
    std::string id;
    std::string display_name;
    std::string email;
    std::string upn; // User Principal Name
    std::vector<std::string> groups;
    bool enabled = true;
    int64_t synced_at{0};
};

struct DirectoryGroup {
    std::string id;
    std::string display_name;
    std::string description;
    std::string mapped_role; // RBAC role this group maps to
    int64_t synced_at{0};
};

enum class SyncProviderType {
    kEntraId,
    kLdap
};

struct SyncStatus {
    std::string provider;  // "entra" or "ldap"
    std::string status;    // "idle", "running", "completed", "failed"
    int64_t last_sync_at{0};
    int64_t next_sync_at{0};
    int user_count{0};
    int group_count{0};
    std::string last_error;
};

struct EntraConfig {
    std::string tenant_id;
    std::string client_id;
    std::string client_secret;
};

struct LdapConfig {
    std::string server;
    int port{389};
    std::string base_dn;
    std::string bind_dn;
    std::string bind_password;
    bool use_ssl{false};
};

// ── DirectorySync ────────────────────────────────────────────────────────────

class DirectorySync {
public:
    explicit DirectorySync(const std::filesystem::path& db_path);
    ~DirectorySync();

    DirectorySync(const DirectorySync&) = delete;
    DirectorySync& operator=(const DirectorySync&) = delete;

    bool is_open() const;

    // ── Sync operations ─────────────────────────────────────────────────

    /// Sync users and groups from Microsoft Entra ID (Azure AD) via Graph API.
    /// Uses OAuth2 client credentials flow to obtain an access token, then
    /// fetches /users and /groups from Microsoft Graph.
    std::expected<void, std::string> sync_entra(const EntraConfig& config);

    /// Sync from on-prem AD via LDAP (stub — full LDAP requires a library not
    /// in vcpkg. Entra ID is available now; LDAP support planned).
    std::expected<void, std::string> sync_ldap(const LdapConfig& config);

    // ── Query ───────────────────────────────────────────────────────────

    /// Get all synced users, optionally filtered by group.
    std::vector<DirectoryUser> get_synced_users(const std::string& group_filter = {}) const;

    /// Get a single synced user by directory object ID.
    std::optional<DirectoryUser> get_user(const std::string& id) const;

    /// Get all synced groups.
    std::vector<DirectoryGroup> get_synced_groups() const;

    /// Get sync status for each configured provider.
    SyncStatus get_status() const;

    // ── Group-to-role mapping ───────────────────────────────────────────

    /// Map a directory group to an RBAC role name.
    void configure_group_role_mapping(const std::string& group_id,
                                      const std::string& role_name);

    /// Remove a group-to-role mapping.
    void remove_group_role_mapping(const std::string& group_id);

    /// Get all group-to-role mappings.
    std::map<std::string, std::string> get_group_role_mappings() const;

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;

    void create_tables();
    std::string generate_id() const;

    // Internal: store fetched users/groups from a sync result
    void store_user(const DirectoryUser& user);
    void store_group(const DirectoryGroup& group);
    void store_membership(const std::string& user_id, const std::string& group_id);
    void clear_memberships();

    // Internal: update sync status
    void update_status(const std::string& provider, const std::string& status,
                       int user_count = 0, int group_count = 0,
                       const std::string& error = {});

    // Internal: WinHTTP GET helper (Windows) / httplib GET (other platforms)
    std::expected<std::string, std::string> http_get(const std::string& url,
                                                     const std::string& bearer_token);

    // Internal: obtain OAuth2 access token via client credentials
    std::expected<std::string, std::string> acquire_token(const EntraConfig& config);
};

} // namespace yuzu::server
