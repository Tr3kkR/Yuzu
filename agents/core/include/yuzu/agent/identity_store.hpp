#pragma once

#include <expected>
#include <filesystem>
#include <string>
#include <string_view>

#include <yuzu/plugin.h>  // for YUZU_EXPORT

namespace yuzu::agent {

struct IdentityError {
    std::string message;
};

/// Resolves the agent ID: returns cli_override if non-empty, otherwise
/// loads from (or generates into) the SQLite database at db_path.
[[nodiscard]] YUZU_EXPORT auto resolve_agent_id(
    std::string_view cli_override,
    const std::filesystem::path& db_path
) -> std::expected<std::string, IdentityError>;

/// Returns the platform-appropriate default data directory for Yuzu.
[[nodiscard]] YUZU_EXPORT auto default_data_dir() -> std::filesystem::path;

}  // namespace yuzu::agent
