#pragma once

#include "config_secret_keys.hpp"

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

struct RuntimeConfigEntry {
    std::string key;
    std::string value;
    std::string updated_by;
    int64_t updated_at{0};
};

/// Persistent runtime configuration overrides.
/// Stores key/value pairs in SQLite that override startup defaults.
/// Only a fixed set of allowed keys is accepted. One of them
/// (oidc_client_secret) IS a secret and is stored plaintext today -
/// its envelope encryption lands with the Postgres migration (ADR-0010).
class RuntimeConfigStore {
public:
    explicit RuntimeConfigStore(const std::filesystem::path& db_path);
    ~RuntimeConfigStore();

    RuntimeConfigStore(const RuntimeConfigStore&) = delete;
    RuntimeConfigStore& operator=(const RuntimeConfigStore&) = delete;

    bool is_open() const;

    /// THE THREE PLAIN READ ACCESSORS REDACT; plaintext requires a `_with_secrets`
    /// name. Naming it at the call site is the point: an emitter that does not think
    /// about secrets gets the safe behaviour.
    /// Redaction being opt-in is how the plaintext secret reached an audit row that
    /// Operator can read, surviving the first round of the fix (governance, this
    /// branch) -- so it is not opt-in on any accessor.
    ///
    /// A secret's value is replaced by redacted_placeholder(). An EMPTY secret is
    /// left empty: there is nothing to protect, and the emptiness is the only
    /// set-vs-unset signal a caller has (GET /api/config derives `is_set` from it).

    /// All entries, secrets redacted.
    std::vector<RuntimeConfigEntry> get_all() const;

    /// All entries with real values. ONE legitimate caller today: the startup
    /// override pass, which must apply the real secret. Anything that EMITS -- a
    /// log, an API response, an audit detail, a dashboard fragment -- must not use
    /// this. Redaction being opt-in is how the plaintext secret reached an audit
    /// row that Operator can read (governance, this branch).
    std::vector<RuntimeConfigEntry> get_all_with_secrets() const;

    /// A single config entry, secret redacted.
    std::optional<RuntimeConfigEntry> get(const std::string& key) const;

    /// A single entry with its real value. Same rule as get_all_with_secrets().
    std::optional<RuntimeConfigEntry> get_with_secrets(const std::string& key) const;

    /// The value of a config key, secret redacted, or empty string if not set.
    std::string get_value(const std::string& key) const;

    /// The real value of a config key, or empty string if not set. Same rule as
    /// get_all_with_secrets(): use only where the credential itself is required.
    std::string get_value_with_secrets(const std::string& key) const;

    /// Set a config value. Returns an error if the key is not in the allow-list, if
    /// validation fails, or if the value is the redaction placeholder for a secret key.
    ///
    /// [[nodiscard]] deliberately: discarding this used to be harmless because the only
    /// failure was an unknown key, which no in-tree caller could produce. The
    /// placeholder guard made it reachable, and a caller that ignored it reported
    /// "saved" for a write the store refused -- with the live in-memory config already
    /// updated, so the two diverged and a restart silently healed it.
    [[nodiscard]] std::expected<void, std::string> set(const std::string& key,
                                                       const std::string& value,
                                         const std::string& updated_by);

    /// Delete a config override (revert to default).
    bool remove(const std::string& key);

    /// Check if a key is in the allow-list of safe runtime-configurable keys.
    static bool is_allowed_key(const std::string& key);

    /// True if this key's VALUE is a credential and must never be emitted in
    /// plaintext - not to a log, not to an API response, not to an audit detail, not
    /// to a config dump. Prefer get_all(), which applies this for you; consult the
    /// predicate directly only where the value does not come from the store (the
    /// PUT handler audits a caller-supplied value, which is the path that leaked
    /// past the first version of this fix).
    static bool is_secret_key(const std::string& key);

    /// What to print in place of a secret. Delegates to the shared leaf so there is
    /// exactly one spelling in the tree (see config_secret_keys.hpp).
    static const char* redacted_placeholder() { return kRedactedPlaceholder; }

    /// Returns the list of allowed config keys.
    static const std::vector<std::string>& allowed_keys();

private:
    sqlite3* db_{nullptr};
    mutable std::mutex mu_;

    void create_tables();
};

} // namespace yuzu::server
