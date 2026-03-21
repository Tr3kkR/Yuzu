/**
 * wifi_plugin.cpp — WiFi network scanning plugin for Yuzu
 *
 * Actions:
 *   "list_networks" — Scans for visible WiFi networks and returns SSID,
 *                     signal strength, security type, channel, and BSSID.
 *   "connected"     — Reports the currently connected WiFi network info.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   key|field1|field2|...
 *
 * Platform implementations:
 *   Windows: WlanEnumInterfaces + WlanGetAvailableNetworkList / WlanQueryInterface
 *   Linux:   nmcli device wifi list / nmcli device wifi show
 *   macOS:   airport -s / airport -I
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <format>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wlanapi.h>
#pragma comment(lib, "wlanapi.lib")
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
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}
#endif

#ifdef _WIN32
// Convert a wide string to UTF-8
std::string wide_to_utf8(const wchar_t* ws) {
    if (!ws || !*ws)
        return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    std::string result(len > 0 ? len - 1 : 0, '\0');
    if (len > 0) {
        WideCharToMultiByte(CP_UTF8, 0, ws, -1, result.data(), len, nullptr, nullptr);
    }
    return result;
}

// Convert DOT11_AUTH_ALGORITHM to human-readable string
const char* auth_to_string(DOT11_AUTH_ALGORITHM auth) {
    switch (auth) {
    case DOT11_AUTH_ALGO_80211_OPEN:
        return "Open";
    case DOT11_AUTH_ALGO_80211_SHARED_KEY:
        return "WEP-Shared";
    case DOT11_AUTH_ALGO_WPA:
        return "WPA-Enterprise";
    case DOT11_AUTH_ALGO_WPA_PSK:
        return "WPA-PSK";
    case DOT11_AUTH_ALGO_WPA_NONE:
        return "WPA-None";
    case DOT11_AUTH_ALGO_RSNA:
        return "WPA2-Enterprise";
    case DOT11_AUTH_ALGO_RSNA_PSK:
        return "WPA2-PSK";
    default:
        return "Unknown";
    }
}

// Convert DOT11_BSS_TYPE to string
const char* bss_type_to_string(DOT11_BSS_TYPE bss) {
    switch (bss) {
    case dot11_BSS_type_infrastructure:
        return "Infrastructure";
    case dot11_BSS_type_independent:
        return "Ad-hoc";
    default:
        return "Unknown";
    }
}
#endif

// ── list_networks action ──────────────────────────────────────────────────

int do_list_networks(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    HANDLE client = nullptr;
    DWORD negotiated_version = 0;
    DWORD result = WlanOpenHandle(2, nullptr, &negotiated_version, &client);
    if (result != ERROR_SUCCESS) {
        ctx.write_output("wifi|error|Cannot open WLAN handle|0|0|none");
        return 1;
    }

    PWLAN_INTERFACE_INFO_LIST iface_list = nullptr;
    result = WlanEnumInterfaces(client, nullptr, &iface_list);
    if (result != ERROR_SUCCESS || !iface_list || iface_list->dwNumberOfItems == 0) {
        ctx.write_output("wifi|error|No wireless interfaces found|0|0|none");
        if (iface_list)
            WlanFreeMemory(iface_list);
        WlanCloseHandle(client, nullptr);
        return 0;
    }

    for (DWORD i = 0; i < iface_list->dwNumberOfItems; ++i) {
        auto& iface = iface_list->InterfaceInfo[i];

        PWLAN_AVAILABLE_NETWORK_LIST net_list = nullptr;
        result =
            WlanGetAvailableNetworkList(client, &iface.InterfaceGuid, 0, nullptr, &net_list);
        if (result != ERROR_SUCCESS || !net_list)
            continue;

        for (DWORD j = 0; j < net_list->dwNumberOfItems; ++j) {
            auto& net = net_list->Network[j];

            // Convert SSID (raw bytes) to string
            std::string ssid(reinterpret_cast<const char*>(net.dot11Ssid.ucSSID),
                             net.dot11Ssid.uSSIDLength);
            if (ssid.empty())
                ssid = "<hidden>";

            auto signal = net.wlanSignalQuality; // 0-100%
            auto security = auth_to_string(net.dot11DefaultAuthAlgorithm);
            auto bss_type = bss_type_to_string(net.dot11BssType);
            bool connected = (net.dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED) != 0;

            ctx.write_output(std::format("wifi|{}|{}|{}|{}|{}", ssid, signal, security,
                                         bss_type, connected ? "true" : "false"));
        }
        WlanFreeMemory(net_list);
    }

    WlanFreeMemory(iface_list);
    WlanCloseHandle(client, nullptr);

#elif defined(__linux__)
    // Use nmcli for structured WiFi scanning
    auto nmcli_out = run_command(
        "nmcli -t -f SSID,SIGNAL,SECURITY,CHAN,BSSID device wifi list 2>/dev/null");
    if (!nmcli_out.empty()) {
        std::istringstream ss(nmcli_out);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty())
                continue;
            // nmcli -t uses ':' as delimiter
            // Fields: SSID:SIGNAL:SECURITY:CHAN:BSSID
            std::istringstream ls(line);
            std::string ssid, signal, security, channel, bssid;
            std::getline(ls, ssid, ':');
            std::getline(ls, signal, ':');
            std::getline(ls, security, ':');
            std::getline(ls, channel, ':');
            std::getline(ls, bssid, ':');

            if (ssid.empty())
                ssid = "<hidden>";
            if (security.empty())
                security = "Open";

            ctx.write_output(std::format("wifi|{}|{}|{}|{}|{}", ssid,
                                         signal.empty() ? "0" : signal, security,
                                         channel.empty() ? "0" : channel,
                                         bssid.empty() ? "-" : bssid));
        }
    } else {
        // Fallback: try iw
        auto iw_out = run_command("iw dev 2>/dev/null | grep Interface | awk '{print $2}'");
        if (!iw_out.empty()) {
            std::istringstream ss(iw_out);
            std::string iface;
            while (std::getline(ss, iface)) {
                if (iface.empty())
                    continue;
                auto scan = run_command(
                    std::format("iwlist {} scan 2>/dev/null | grep -E 'ESSID|Quality|Encryption'",
                                iface)
                        .c_str());
                if (!scan.empty()) {
                    ctx.write_output(std::format("wifi|scan_output|{}", scan));
                }
            }
        } else {
            ctx.write_output("wifi|error|No wireless tools available (nmcli/iw)|0|0|none");
        }
    }

#elif defined(__APPLE__)
    // macOS: use airport utility
    auto airport_out = run_command(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport "
        "-s 2>/dev/null");
    if (!airport_out.empty()) {
        std::istringstream ss(airport_out);
        std::string line;
        bool header_skipped = false;
        while (std::getline(ss, line)) {
            if (!header_skipped) {
                header_skipped = true;
                continue; // Skip header line
            }
            if (line.empty())
                continue;

            // airport -s output is fixed-width:
            // SSID  BSSID  RSSI  CHANNEL  HT  CC  SECURITY
            // The SSID is right-padded, BSSID starts at a fixed column
            // Parse carefully since SSIDs can contain spaces
            if (line.size() < 40)
                continue;

            // Find BSSID pattern (XX:XX:XX:XX:XX:XX) to anchor parsing
            auto bssid_start = line.find_first_of("0123456789abcdef", 0);
            // Look for MAC address pattern
            std::string ssid, bssid, rssi, channel, security;

            // Simple approach: split from the right where fixed fields are
            // BSSID is at roughly column 33, then RSSI, CHANNEL, HT, CC, SECURITY
            std::istringstream ls(line);
            std::string token;
            std::vector<std::string> tokens;
            while (ls >> token) {
                tokens.push_back(token);
            }

            if (tokens.size() >= 7) {
                // Last token is SECURITY, then CC, HT, CHANNEL, RSSI, BSSID
                // SSID is everything before BSSID
                security = tokens.back();
                // Collect remaining security tokens if they contain WPA/WEP
                size_t sec_start = tokens.size() - 1;
                while (sec_start > 0 && (tokens[sec_start - 1].find("WPA") != std::string::npos ||
                                          tokens[sec_start - 1].find("WEP") != std::string::npos ||
                                          tokens[sec_start - 1] == "--")) {
                    security = tokens[sec_start - 1] + " " + security;
                    --sec_start;
                }
                // Work backwards: CC, HT, CHANNEL, RSSI, BSSID
                if (sec_start >= 6) {
                    // cc = tokens[sec_start - 1]
                    // ht = tokens[sec_start - 2]
                    channel = tokens[sec_start - 3];
                    rssi = tokens[sec_start - 4];
                    bssid = tokens[sec_start - 5];
                    // SSID is everything before BSSID
                    ssid = tokens[0];
                    for (size_t k = 1; k < sec_start - 5; ++k) {
                        ssid += " " + tokens[k];
                    }
                }
            }

            if (ssid.empty())
                ssid = "<hidden>";
            if (security.empty())
                security = "Open";

            ctx.write_output(std::format("wifi|{}|{}|{}|{}|{}", ssid, rssi.empty() ? "0" : rssi,
                                         security, channel.empty() ? "0" : channel,
                                         bssid.empty() ? "-" : bssid));
        }
    } else {
        ctx.write_output("wifi|error|airport command not available|0|0|none");
    }
#endif
    return 0;
}

// ── connected action ──────────────────────────────────────────────────────

int do_connected(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    HANDLE client = nullptr;
    DWORD negotiated_version = 0;
    DWORD result = WlanOpenHandle(2, nullptr, &negotiated_version, &client);
    if (result != ERROR_SUCCESS) {
        ctx.write_output("connected|none|Not connected|0|none|none");
        return 0;
    }

    PWLAN_INTERFACE_INFO_LIST iface_list = nullptr;
    result = WlanEnumInterfaces(client, nullptr, &iface_list);
    if (result != ERROR_SUCCESS || !iface_list) {
        WlanCloseHandle(client, nullptr);
        ctx.write_output("connected|none|Not connected|0|none|none");
        return 0;
    }

    bool found = false;
    for (DWORD i = 0; i < iface_list->dwNumberOfItems; ++i) {
        auto& iface = iface_list->InterfaceInfo[i];
        if (iface.isState != wlan_interface_state_connected)
            continue;

        // Query connection attributes
        PWLAN_CONNECTION_ATTRIBUTES conn_attrs = nullptr;
        DWORD attr_size = 0;
        WLAN_OPCODE_VALUE_TYPE opcode_type;
        result = WlanQueryInterface(client, &iface.InterfaceGuid,
                                    wlan_intf_opcode_current_connection, nullptr, &attr_size,
                                    reinterpret_cast<PVOID*>(&conn_attrs), &opcode_type);
        if (result != ERROR_SUCCESS || !conn_attrs)
            continue;

        // Extract SSID
        std::string ssid(
            reinterpret_cast<const char*>(
                conn_attrs->wlanAssociationAttributes.dot11Ssid.ucSSID),
            conn_attrs->wlanAssociationAttributes.dot11Ssid.uSSIDLength);

        auto signal = conn_attrs->wlanAssociationAttributes.wlanSignalQuality;
        auto security = auth_to_string(
            conn_attrs->wlanSecurityAttributes.dot11AuthAlgorithm);

        // Format BSSID
        auto* bssid = conn_attrs->wlanAssociationAttributes.dot11Bssid;
        auto bssid_str =
            std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", bssid[0], bssid[1],
                        bssid[2], bssid[3], bssid[4], bssid[5]);

        auto iface_name = wide_to_utf8(iface.strInterfaceDescription);

        ctx.write_output(std::format("connected|{}|{}|{}|{}|{}", ssid, signal, security,
                                     bssid_str, iface_name));
        found = true;

        WlanFreeMemory(conn_attrs);
    }

    if (!found) {
        ctx.write_output("connected|none|Not connected|0|none|none");
    }

    WlanFreeMemory(iface_list);
    WlanCloseHandle(client, nullptr);

#elif defined(__linux__)
    // Use nmcli to get current connection info
    auto nmcli_out = run_command(
        "nmcli -t -f GENERAL.CONNECTION,WIFI.SSID,WIFI.SIGNAL,WIFI.SECURITY,WIFI.BSSID "
        "device show 2>/dev/null | head -20");
    if (!nmcli_out.empty()) {
        std::istringstream ss(nmcli_out);
        std::string line;
        std::string ssid, signal, security, bssid, connection;
        while (std::getline(ss, line)) {
            auto colon = line.find(':');
            if (colon == std::string::npos)
                continue;
            auto key = line.substr(0, colon);
            auto val = line.substr(colon + 1);
            if (key == "GENERAL.CONNECTION")
                connection = val;
            else if (key == "WIFI.SSID")
                ssid = val;
            else if (key == "WIFI.SIGNAL")
                signal = val;
            else if (key == "WIFI.SECURITY")
                security = val;
            else if (key == "WIFI.BSSID")
                bssid = val;
        }

        if (!ssid.empty()) {
            ctx.write_output(std::format("connected|{}|{}|{}|{}|{}", ssid,
                                         signal.empty() ? "0" : signal,
                                         security.empty() ? "Open" : security,
                                         bssid.empty() ? "-" : bssid,
                                         connection.empty() ? "-" : connection));
        } else {
            // Fallback: iwconfig
            auto iw_out = run_command("iwconfig 2>/dev/null | grep -E 'ESSID|Signal'");
            if (!iw_out.empty() && iw_out.find("ESSID:off") == std::string::npos) {
                ctx.write_output(std::format("connected|{}|0|unknown|-|-", iw_out));
            } else {
                ctx.write_output("connected|none|Not connected|0|none|none");
            }
        }
    } else {
        ctx.write_output("connected|none|Not connected|0|none|none");
    }

#elif defined(__APPLE__)
    auto airport_out = run_command(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport "
        "-I 2>/dev/null");
    if (!airport_out.empty()) {
        std::istringstream ss(airport_out);
        std::string line;
        std::string ssid, rssi, security, bssid, channel;
        while (std::getline(ss, line)) {
            // Trim leading whitespace
            auto start = line.find_first_not_of(" \t");
            if (start == std::string::npos)
                continue;
            auto trimmed = line.substr(start);

            if (trimmed.starts_with("SSID: "))
                ssid = trimmed.substr(6);
            else if (trimmed.starts_with("agrCtlRSSI: "))
                rssi = trimmed.substr(12);
            else if (trimmed.starts_with("link auth: "))
                security = trimmed.substr(11);
            else if (trimmed.starts_with("BSSID: "))
                bssid = trimmed.substr(7);
            else if (trimmed.starts_with("channel: "))
                channel = trimmed.substr(9);
        }

        if (!ssid.empty()) {
            ctx.write_output(std::format("connected|{}|{}|{}|{}|{}", ssid,
                                         rssi.empty() ? "0" : rssi,
                                         security.empty() ? "Open" : security,
                                         bssid.empty() ? "-" : bssid,
                                         channel.empty() ? "0" : channel));
        } else {
            ctx.write_output("connected|none|Not connected|0|none|none");
        }
    } else {
        ctx.write_output("connected|none|Not connected|0|none|none");
    }
#endif
    return 0;
}

} // namespace

class WifiPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "wifi"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Scans visible WiFi networks and reports current connection status";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list_networks", "connected", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "list_networks")
            return do_list_networks(ctx);
        if (action == "connected")
            return do_connected(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(WifiPlugin)
