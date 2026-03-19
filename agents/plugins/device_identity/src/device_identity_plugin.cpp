/**
 * device_identity_plugin.cpp — Device identity plugin for Yuzu
 *
 * Actions:
 *   "device_name" — Returns the machine hostname.
 *   "domain"      — Returns DNS/AD domain and join status.
 *   "ou"          — Returns Active Directory organizational unit path.
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <format>
#include <string>
#include <string_view>

#if defined(__linux__) || defined(__APPLE__)
#include <fstream>
#include <unistd.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define SECURITY_WIN32
#include <windows.h>
#include <lm.h>       // NetGetJoinInformation, NetApiBufferFree
#include <security.h> // GetComputerObjectNameA
#endif

namespace {

// ── subprocess helper (Linux / macOS) ──────────────────────────────────────

#if defined(__linux__) || defined(__APPLE__)
std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
    pclose(pipe);
    // Trim trailing newline
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}
#endif

// ── device_name action ─────────────────────────────────────────────────────

int do_device_name(yuzu::CommandContext& ctx) {
#if defined(__linux__) || defined(__APPLE__)
    char hostname[256]{};
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        ctx.write_output(std::format("device_name|{}", hostname));
    } else {
        ctx.write_output("device_name|unknown");
    }

#elif defined(_WIN32)
    DWORD size = 0;
    GetComputerNameExA(ComputerNamePhysicalDnsHostname, nullptr, &size);
    if (size > 0) {
        std::string buf(size, '\0');
        if (GetComputerNameExA(ComputerNamePhysicalDnsHostname, buf.data(), &size)) {
            buf.resize(size);
            ctx.write_output(std::format("device_name|{}", buf));
        } else {
            ctx.write_output("device_name|unknown");
        }
    } else {
        ctx.write_output("device_name|unknown");
    }

#else
    ctx.write_output("device_name|unknown");
#endif
    return 0;
}

// ── domain action ──────────────────────────────────────────────────────────

#ifdef __linux__
int do_domain(yuzu::CommandContext& ctx) {
    // Try /etc/resolv.conf for DNS domain
    std::string domain;
    {
        std::ifstream resolv("/etc/resolv.conf");
        std::string line;
        while (std::getline(resolv, line)) {
            // "domain example.com" or "search example.com other.com"
            if (line.starts_with("domain ") || line.starts_with("search ")) {
                auto pos = line.find(' ');
                if (pos != std::string::npos) {
                    auto val_start = line.find_first_not_of(' ', pos);
                    if (val_start != std::string::npos) {
                        // For "search", take the first entry
                        auto val_end = line.find_first_of(" \t", val_start);
                        domain = line.substr(val_start, val_end == std::string::npos
                                                            ? std::string::npos
                                                            : val_end - val_start);
                    }
                }
                if (line.starts_with("domain "))
                    break; // prefer "domain" over "search"
            }
        }
    }

    if (domain.empty()) {
        domain = "N/A";
    }
    ctx.write_output(std::format("domain|{}", domain));

    // Check AD join via realm or sssd
    bool joined = false;
    auto realm_out = run_command("realm list 2>/dev/null");
    if (!realm_out.empty()) {
        joined = true;
    } else {
        std::ifstream sssd("/etc/sssd/sssd.conf");
        if (sssd.good()) {
            std::string line;
            while (std::getline(sssd, line)) {
                if (line.find("ad_domain") != std::string::npos) {
                    joined = true;
                    break;
                }
            }
        }
    }
    ctx.write_output(std::format("joined|{}", joined ? "true" : "false"));
    return 0;
}
#endif

#ifdef __APPLE__
int do_domain(yuzu::CommandContext& ctx) {
    // Check AD binding via dsconfigad
    auto ad_out = run_command("dsconfigad -show 2>/dev/null");
    if (!ad_out.empty() && ad_out.find("Active Directory Domain") != std::string::npos) {
        // Extract domain from "Active Directory Domain = example.com"
        auto pos = ad_out.find("Active Directory Domain");
        if (pos != std::string::npos) {
            auto eq = ad_out.find('=', pos);
            if (eq != std::string::npos) {
                auto val_start = ad_out.find_first_not_of(" \t", eq + 1);
                auto val_end = ad_out.find_first_of("\r\n", val_start);
                auto domain =
                    ad_out.substr(val_start, val_end == std::string::npos ? std::string::npos
                                                                          : val_end - val_start);
                ctx.write_output(std::format("domain|{}", domain));
                ctx.write_output("joined|true");
                return 0;
            }
        }
    }

    // Fall back to hostname domain suffix
    auto fqdn = run_command("hostname -f 2>/dev/null");
    auto dot = fqdn.find('.');
    if (dot != std::string::npos) {
        ctx.write_output(std::format("domain|{}", fqdn.substr(dot + 1)));
    } else {
        ctx.write_output("domain|N/A");
    }
    ctx.write_output("joined|false");
    return 0;
}
#endif

#ifdef _WIN32
int do_domain(yuzu::CommandContext& ctx) {
    LPWSTR name_buf = nullptr;
    NETSETUP_JOIN_STATUS join_status{};

    auto status = NetGetJoinInformation(nullptr, &name_buf, &join_status);
    if (status == NERR_Success && name_buf) {
        // Convert wide string to narrow
        int len = WideCharToMultiByte(CP_UTF8, 0, name_buf, -1, nullptr, 0, nullptr, nullptr);
        std::string domain(len > 0 ? len - 1 : 0, '\0');
        if (len > 0) {
            WideCharToMultiByte(CP_UTF8, 0, name_buf, -1, domain.data(), len, nullptr, nullptr);
        }
        NetApiBufferFree(name_buf);

        ctx.write_output(std::format("domain|{}", domain.empty() ? "N/A" : domain));
        ctx.write_output(
            std::format("joined|{}", join_status == NetSetupDomainName ? "true" : "false"));
    } else {
        ctx.write_output("domain|N/A");
        ctx.write_output("joined|false");
    }
    return 0;
}
#endif

// ── ou action ──────────────────────────────────────────────────────────────

#ifdef __linux__
int do_ou(yuzu::CommandContext& ctx) {
    // Try realm list for OU
    auto realm_out = run_command("realm list 2>/dev/null");
    if (!realm_out.empty()) {
        // Look for "computer-ou:" line
        auto pos = realm_out.find("computer-ou:");
        if (pos != std::string::npos) {
            auto val_start = realm_out.find_first_not_of(" \t:", pos + 12);
            if (val_start != std::string::npos) {
                auto val_end = realm_out.find_first_of("\r\n", val_start);
                auto ou =
                    realm_out.substr(val_start, val_end == std::string::npos ? std::string::npos
                                                                             : val_end - val_start);
                ctx.write_output(std::format("ou|{}", ou));
                return 0;
            }
        }
    }

    // Try sssd.conf for ldap_default_bind_dn or krb5_realm
    std::ifstream sssd("/etc/sssd/sssd.conf");
    if (sssd.good()) {
        std::string line;
        while (std::getline(sssd, line)) {
            if (line.find("ldap_default_bind_dn") != std::string::npos) {
                auto eq = line.find('=');
                if (eq != std::string::npos) {
                    auto val = line.substr(eq + 1);
                    // Trim leading whitespace
                    auto start = val.find_first_not_of(" \t");
                    if (start != std::string::npos)
                        val = val.substr(start);
                    ctx.write_output(std::format("ou|{}", val));
                    return 0;
                }
            }
        }
    }

    ctx.write_output("ou|N/A");
    return 0;
}
#endif

#ifdef __APPLE__
int do_ou(yuzu::CommandContext& ctx) {
    auto ad_out = run_command("dsconfigad -show 2>/dev/null");
    if (!ad_out.empty()) {
        // Look for "Organizational Unit" line
        auto pos = ad_out.find("Organizational Unit");
        if (pos != std::string::npos) {
            auto eq = ad_out.find('=', pos);
            if (eq != std::string::npos) {
                auto val_start = ad_out.find_first_not_of(" \t", eq + 1);
                auto val_end = ad_out.find_first_of("\r\n", val_start);
                auto ou =
                    ad_out.substr(val_start, val_end == std::string::npos ? std::string::npos
                                                                          : val_end - val_start);
                ctx.write_output(std::format("ou|{}", ou));
                return 0;
            }
        }
    }
    ctx.write_output("ou|N/A");
    return 0;
}
#endif

#ifdef _WIN32
int do_ou(yuzu::CommandContext& ctx) {
    // GetComputerObjectNameA with NameFullyQualifiedDN returns the full DN,
    // e.g. "CN=WORKSTATION01,OU=Workstations,DC=corp,DC=example,DC=com"
    // We extract the OU components from the DN.
    DWORD size = 0;
    GetComputerObjectNameA(NameFullyQualifiedDN, nullptr, &size);
    if (size > 0) {
        std::string dn(size, '\0');
        if (GetComputerObjectNameA(NameFullyQualifiedDN, dn.data(), &size)) {
            dn.resize(size);
            // Extract OU= components from the DN
            // Find first OU= after the CN= prefix
            auto ou_start = dn.find("OU=");
            if (ou_start != std::string::npos) {
                ctx.write_output(std::format("ou|{}", dn.substr(ou_start)));
                return 0;
            }
        }
    }
    ctx.write_output("ou|N/A");
    return 0;
}
#endif

} // namespace

class DeviceIdentityPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "device_identity"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports device hostname, domain membership, and AD organizational unit";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"device_name", "domain", "ou", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "device_name")
            return do_device_name(ctx);
        if (action == "domain")
            return do_domain(ctx);
        if (action == "ou")
            return do_ou(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(DeviceIdentityPlugin)
