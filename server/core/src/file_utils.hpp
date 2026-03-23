#pragma once

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>

#include <spdlog/spdlog.h>

namespace yuzu::server::detail {

/// Read entire file contents into a string. Returns empty string on failure.
inline std::string read_file_contents(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f)
        return {};
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

/// Validate that a private key file is not readable by group or others (Unix).
/// Returns true if permissions are acceptable or on Windows (ACL-based).
[[nodiscard]] inline bool validate_key_file_permissions(const std::filesystem::path& key_path,
                                                         std::string_view label) {
#ifdef _WIN32
    // Windows uses ACLs, not POSIX mode bits. Log advisory and proceed.
    spdlog::debug("{}: skipping Unix permission check on Windows for {}", label,
                  key_path.string());
    return true;
#else
    std::error_code ec;
    auto perms = std::filesystem::status(key_path, ec).permissions();
    if (ec) {
        spdlog::error("{}: cannot stat key file {}: {}", label, key_path.string(), ec.message());
        return false;
    }
    using fp = std::filesystem::perms;
    auto bad = perms & (fp::group_read | fp::group_write | fp::group_exec | fp::others_read |
                        fp::others_write | fp::others_exec);
    if (bad != fp::none) {
        spdlog::error("{}: private key {} has overly permissive file permissions. "
                      "Run: chmod 600 {}",
                      label, key_path.string(), key_path.string());
        return false;
    }
    return true;
#endif
}

} // namespace yuzu::server::detail
