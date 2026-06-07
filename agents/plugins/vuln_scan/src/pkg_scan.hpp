#pragma once

#include <string>
#include <vector>
#include <cstdio>
#include <memory>
#include <sstream>
#include <nlohmann/json.hpp>

namespace yuzu::vuln {

struct LangPkgInfo {
    std::string ecosystem;  // "npm", "PyPI", "crates.io", "RubyGems", "NuGet"
    std::string name;
    std::string version;
};

/// Detect globally installed language-specific packages.
/// Probes npm, pip, cargo, gem, and dotnet tool managers via popen.
/// Returns empty vector if tools are not found or detection fails.
std::vector<LangPkgInfo> get_lang_packages();

}  // namespace yuzu::vuln

// IMPLEMENTATION (inline for header-only library)

#include <cstring>
#include <cctype>

#ifdef _WIN32
#define POPEN _popen
#define PCLOSE _pclose
#else
#define POPEN popen
#define PCLOSE pclose
#endif

namespace yuzu::vuln {

static bool command_exists_local(const char* cmd) {
#ifdef _WIN32
    std::string where_cmd = std::string("where ") + cmd + " >NUL 2>&1";
    return system(where_cmd.c_str()) == 0;
#else
    std::string cmd_str = std::string("command -v ") + cmd + " >/dev/null 2>&1";
    return system(cmd_str.c_str()) == 0;
#endif
}

static std::string read_command_output(const char* cmd) {
    std::string result;
    FILE* pipe = POPEN(cmd, "r");
    if (!pipe) return result;

    char buffer[256];
    while (std::fgets(buffer, sizeof(buffer), pipe)) {
        result += buffer;
    }
    PCLOSE(pipe);
    return result;
}

// Parse npm list -g --depth=0 --json output
// Output: {"dependencies":{"pkg1":{"version":"1.0.0"},...}}
// Requires nlohmann/json which is already a dep of vuln_scan_plugin.cpp
static std::vector<LangPkgInfo> detect_npm_packages() {
    std::vector<LangPkgInfo> pkgs;
    if (!command_exists_local("npm")) return pkgs;

    std::string output = read_command_output("npm list -g --depth=0 --json 2>/dev/null");
    if (output.empty()) return pkgs;

    try {
        auto j = nlohmann::json::parse(output);
        if (j.contains("dependencies") && j["dependencies"].is_object()) {
            for (auto& [name, data] : j["dependencies"].items()) {
                if (data.contains("version")) {
                    pkgs.push_back({
                        "npm",
                        name,
                        data["version"].get<std::string>()
                    });
                }
            }
        }
    } catch (...) {
        // JSON parse error — silently skip
    }
    return pkgs;
}

// Parse pip list --format=json output
// Output: [{"name":"pkg1","version":"1.0.0"},...]
static std::vector<LangPkgInfo> detect_pypi_packages() {
    std::vector<LangPkgInfo> pkgs;
    const char* pip_cmd = command_exists_local("pip3") ? "pip3" : "pip";
    if (!command_exists_local(pip_cmd)) return pkgs;

    std::string cmd = std::string(pip_cmd) + " list --format=json 2>/dev/null";
    std::string output = read_command_output(cmd.c_str());
    if (output.empty()) return pkgs;

    try {
        auto j = nlohmann::json::parse(output);
        if (j.is_array()) {
            for (const auto& item : j) {
                if (item.contains("name") && item.contains("version")) {
                    pkgs.push_back({
                        "PyPI",
                        item["name"].get<std::string>(),
                        item["version"].get<std::string>()
                    });
                }
            }
        }
    } catch (...) {
        // JSON parse error — silently skip
    }
    return pkgs;
}

// Parse cargo install --list output
// Output lines: "pkg1 v1.0.0:\n"
static std::vector<LangPkgInfo> detect_cargo_packages() {
    std::vector<LangPkgInfo> pkgs;
    if (!command_exists_local("cargo")) return pkgs;

    std::string output = read_command_output("cargo install --list 2>/dev/null");
    if (output.empty()) return pkgs;

    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        // Format: "name v1.0.0:"
        size_t space_pos = line.find(' ');
        if (space_pos == std::string::npos) continue;

        std::string name = line.substr(0, space_pos);
        std::string rest = line.substr(space_pos + 1);

        // Strip leading 'v' and trailing ':'
        size_t v_pos = rest.find('v');
        if (v_pos == std::string::npos) continue;

        std::string version = rest.substr(v_pos + 1);
        size_t colon_pos = version.find(':');
        if (colon_pos != std::string::npos) {
            version = version.substr(0, colon_pos);
        }

        // Trim whitespace
        while (!version.empty() && std::isspace(version.back())) {
            version.pop_back();
        }

        if (!name.empty() && !version.empty()) {
            pkgs.push_back({"crates.io", name, version});
        }
    }
    return pkgs;
}

// Parse gem list output
// Output lines: "name (v1, v2, ...)"
// Take the first (newest) version
static std::vector<LangPkgInfo> detect_gem_packages() {
    std::vector<LangPkgInfo> pkgs;
    if (!command_exists_local("gem")) return pkgs;

    std::string output = read_command_output("gem list 2>/dev/null");
    if (output.empty()) return pkgs;

    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        size_t paren_pos = line.find('(');
        if (paren_pos == std::string::npos) continue;

        std::string name = line.substr(0, paren_pos);
        // Trim whitespace from name
        while (!name.empty() && std::isspace(name.back())) {
            name.pop_back();
        }

        std::string versions_str = line.substr(paren_pos + 1);
        size_t close_paren = versions_str.find(')');
        if (close_paren != std::string::npos) {
            versions_str = versions_str.substr(0, close_paren);
        }

        // Extract first version (comma-separated, each may have leading 'v')
        size_t comma_pos = versions_str.find(',');
        std::string first_version = versions_str.substr(0, comma_pos);

        // Trim and strip leading 'v'
        while (!first_version.empty() && std::isspace(first_version.front())) {
            first_version = first_version.substr(1);
        }
        while (!first_version.empty() && std::isspace(first_version.back())) {
            first_version.pop_back();
        }
        if (!first_version.empty() && first_version[0] == 'v') {
            first_version = first_version.substr(1);
        }

        if (!name.empty() && !first_version.empty()) {
            pkgs.push_back({"RubyGems", name, first_version});
        }
    }
    return pkgs;
}

// Parse dotnet tool list -g output
// Tabular format: skip 2 header lines, each row is "name  version  commands"
static std::vector<LangPkgInfo> detect_nuget_packages() {
    std::vector<LangPkgInfo> pkgs;
#ifdef _WIN32
    if (!command_exists_local("dotnet")) return pkgs;

    std::string output = read_command_output("dotnet tool list -g 2>/dev/null");
    if (output.empty()) return pkgs;

    std::istringstream stream(output);
    std::string line;
    int line_num = 0;
    while (std::getline(stream, line)) {
        line_num++;
        if (line_num <= 2) continue;  // Skip header

        // Columns are space/tab separated: name  version  (commands)
        // Split by whitespace
        std::istringstream line_stream(line);
        std::string name, version;
        if (line_stream >> name >> version) {
            pkgs.push_back({"NuGet", name, version});
        }
    }
#endif
    return pkgs;
}

inline std::vector<LangPkgInfo> get_lang_packages() {
    std::vector<LangPkgInfo> all_pkgs;

    auto npm_pkgs = detect_npm_packages();
    all_pkgs.insert(all_pkgs.end(), npm_pkgs.begin(), npm_pkgs.end());

    auto pypi_pkgs = detect_pypi_packages();
    all_pkgs.insert(all_pkgs.end(), pypi_pkgs.begin(), pypi_pkgs.end());

    auto cargo_pkgs = detect_cargo_packages();
    all_pkgs.insert(all_pkgs.end(), cargo_pkgs.begin(), cargo_pkgs.end());

    auto gem_pkgs = detect_gem_packages();
    all_pkgs.insert(all_pkgs.end(), gem_pkgs.begin(), gem_pkgs.end());

    auto nuget_pkgs = detect_nuget_packages();
    all_pkgs.insert(all_pkgs.end(), nuget_pkgs.begin(), nuget_pkgs.end());

    return all_pkgs;
}

}  // namespace yuzu::vuln
