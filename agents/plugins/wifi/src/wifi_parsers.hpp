#pragma once

/**
 * wifi_parsers.hpp — pure parse/format helpers for the wifi plugin's
 * list_networks/connected records.
 *
 * Header-only, no I/O, no spdlog (services_parsers.hpp discipline): every
 * function here takes already-captured tool text (nmcli/iw/iwlist/iwconfig/
 * airport/system_profiler) or already-unwrapped NetworkManager D-Bus
 * property values, and returns a structured/pure result. wifi_plugin.cpp
 * owns every I/O boundary — the bounded argv runner AND the sd-bus reads —
 * and hands this header only plain data, so all of it is fixture-testable
 * (tests/unit/test_wifi_parsers.cpp) without a subprocess, a live
 * NetworkManager host, or Wi-Fi hardware.
 *
 * Two record shapes:
 *   WifiNetworkRow    — one `wifi|SSID|SIGNAL|SECURITY|CHANNEL|BSSID` row
 *                       (list_networks).
 *   WifiConnectedRow  — one `connected|SSID|SIGNAL|SECURITY|BSSID|<col5>`
 *                       row (connected). On Linux <col5> is historically the
 *                       nmcli GENERAL.CONNECTION profile name; the D-Bus leg
 *                       uses the device's Interface name instead (see
 *                       nm_ap_to_connected_row) — a deliberate, documented
 *                       deviation, not an oversight (see the package report).
 *
 * Every field returned here is still RAW (not yet run through
 * yuzu::util::safe_output_field) — wifi_plugin.cpp applies sof() once, at
 * the single emission site, exactly as it does today for every source
 * (nmcli/airport/CoreWLAN alike), so this header never needs to know about
 * the plugin wire-safety helper.
 */

#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::wifi {

// One row of the `wifi|SSID|SIGNAL|SECURITY|CHANNEL|BSSID` list_networks
// record.
struct WifiNetworkRow {
    std::string ssid;
    std::string signal;
    std::string security;
    std::string channel;
    std::string bssid;
};

// One row of the `connected|SSID|SIGNAL|SECURITY|BSSID|<col5>` record.
struct WifiConnectedRow {
    std::string ssid;
    std::string signal;
    std::string security;
    std::string bssid;
    std::string connection; // nmcli: GENERAL.CONNECTION; D-Bus leg: Device.Interface
};

// ── nmcli -t terse-output parsing ───────────────────────────────────────

// Splits one nmcli -t (terse) line on ':' honouring nmcli's own backslash
// escaping (`\:` is a literal colon inside a field, `\\` a literal
// backslash) -- a naive split on every ':' truncates any SSID/value that
// legitimately contains a colon. A trailing lone backslash (nmcli never
// emits one) is kept as a literal backslash rather than dropped.
inline std::vector<std::string> split_nmcli_terse_line(std::string_view line) {
    std::vector<std::string> fields;
    std::string cur;
    bool escaped = false;
    for (char c : line) {
        if (escaped) {
            cur += c;
            escaped = false;
        } else if (c == '\\') {
            escaped = true;
        } else if (c == ':') {
            fields.push_back(std::move(cur));
            cur.clear();
        } else {
            cur += c;
        }
    }
    if (escaped)
        cur += '\\';
    fields.push_back(std::move(cur));
    return fields;
}

// Parses `nmcli -t -f SSID,SIGNAL,SECURITY,CHAN,BSSID device wifi list`
// output into rows, applying the same "<hidden>"/"Open"/"0"/"-" defaults
// the plugin has always applied to blank fields. Blank lines are skipped;
// a short line (missing trailing fields) leaves the missing columns blank
// and defaults them the same way.
inline std::vector<WifiNetworkRow> parse_nmcli_wifi_list(std::string_view raw) {
    std::vector<WifiNetworkRow> rows;
    std::istringstream ss{std::string{raw}};
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty())
            continue;
        auto fields = split_nmcli_terse_line(line);
        WifiNetworkRow row;
        row.ssid = fields.size() > 0 ? fields[0] : std::string{};
        row.signal = fields.size() > 1 ? fields[1] : std::string{};
        row.security = fields.size() > 2 ? fields[2] : std::string{};
        row.channel = fields.size() > 3 ? fields[3] : std::string{};
        row.bssid = fields.size() > 4 ? fields[4] : std::string{};
        if (row.ssid.empty())
            row.ssid = "<hidden>";
        if (row.security.empty())
            row.security = "Open";
        if (row.signal.empty())
            row.signal = "0";
        if (row.channel.empty())
            row.channel = "0";
        if (row.bssid.empty())
            row.bssid = "-";
        rows.push_back(std::move(row));
    }
    return rows;
}

// Parses `nmcli -t -f GENERAL.CONNECTION,WIFI.SSID,WIFI.SIGNAL,
// WIFI.SECURITY,WIFI.BSSID device show` output (KEY:VALUE lines) into a
// connected row. A straight move of the plugin's existing key:value split
// (first ':' only -- keys never contain one) with no new escape handling,
// so this leg's output stays byte-for-byte identical to today's. Returns
// std::nullopt when no WIFI.SSID value was found (mirrors the plugin's
// existing "ssid.empty() -> fall through to iwconfig" branch).
inline std::optional<WifiConnectedRow> parse_nmcli_device_show(std::string_view raw) {
    std::string ssid, signal, security, bssid, connection;
    std::istringstream ss{std::string{raw}};
    std::string line;
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
    if (ssid.empty())
        return std::nullopt;
    WifiConnectedRow row;
    row.ssid = ssid;
    row.signal = signal.empty() ? "0" : signal;
    row.security = security.empty() ? "Open" : security;
    row.bssid = bssid.empty() ? "-" : bssid;
    row.connection = connection.empty() ? "-" : connection;
    return row;
}

// ── iw / iwlist / iwconfig text filtering (replaces the deleted
// `| grep ... | awk ...` shell pipelines) ───────────────────────────────

// Extracts interface names from `iw dev` output -- replaces
// `iw dev | grep Interface | awk '{print $2}'`. Matches any line
// containing "Interface" and takes that line's second whitespace-separated
// token, same as the deleted awk expression.
inline std::vector<std::string> parse_iw_dev_interfaces(std::string_view raw) {
    std::vector<std::string> ifaces;
    std::istringstream ss{std::string{raw}};
    std::string line;
    while (std::getline(ss, line)) {
        if (line.find("Interface") == std::string::npos)
            continue;
        std::istringstream ls(line);
        std::vector<std::string> tokens;
        std::string tok;
        while (ls >> tok)
            tokens.push_back(tok);
        if (tokens.size() >= 2)
            ifaces.push_back(tokens[1]);
    }
    return ifaces;
}

// Filters `iwlist <iface> scan` output down to the ESSID/Quality/Encryption
// lines -- replaces `| grep -E 'ESSID|Quality|Encryption'`. Matching lines
// are joined with '\n', preserving the grep-piped shape the plugin still
// emits as one opaque `wifi|scan_output|...` field.
inline std::string filter_iwlist_scan_lines(std::string_view raw) {
    std::string out;
    std::istringstream ss{std::string{raw}};
    std::string line;
    bool first = true;
    while (std::getline(ss, line)) {
        if (line.find("ESSID") == std::string::npos && line.find("Quality") == std::string::npos &&
            line.find("Encryption") == std::string::npos)
            continue;
        if (!first)
            out += '\n';
        out += line;
        first = false;
    }
    return out;
}

// Filters `iwconfig` output down to the ESSID/Signal lines -- replaces
// `| grep -E 'ESSID|Signal'`. Same join shape as filter_iwlist_scan_lines.
inline std::string filter_iwconfig_essid_signal_lines(std::string_view raw) {
    std::string out;
    std::istringstream ss{std::string{raw}};
    std::string line;
    bool first = true;
    while (std::getline(ss, line)) {
        if (line.find("ESSID") == std::string::npos && line.find("Signal") == std::string::npos)
            continue;
        if (!first)
            out += '\n';
        out += line;
        first = false;
    }
    return out;
}

// Applies the plugin's existing iwconfig connected-fallback rule to an
// already ESSID/Signal-filtered blob: empty, or reporting "ESSID:off"
// (not associated), means std::nullopt (-> "Not connected"); anything else
// is returned as-is (the plugin embeds it as one opaque field, unchanged
// from today -- this fallback has never parsed individual ESSID/Signal
// values out of the blob).
inline std::optional<std::string> parse_iwconfig_essid_blob(std::string_view raw) {
    if (raw.empty())
        return std::nullopt;
    if (raw.find("ESSID:off") != std::string_view::npos)
        return std::nullopt;
    return std::string{raw};
}

// ── macOS airport / system_profiler text parsing ────────────────────────

// Parses `airport -s` fixed-width output into rows. A straight move of the
// plugin's existing token-based reconstruction (SSID can contain spaces, so
// the columns are recovered by walking back from the known-fixed tail:
// SECURITY, CC, HT, CHANNEL, RSSI, BSSID, with everything before BSSID
// re-joined as the SSID) -- unchanged from today, byte-for-byte.
inline std::vector<WifiNetworkRow> parse_airport_scan(std::string_view raw) {
    std::vector<WifiNetworkRow> rows;
    if (raw.empty())
        return rows;
    std::istringstream ss{std::string{raw}};
    std::string line;
    bool header_skipped = false;
    while (std::getline(ss, line)) {
        if (!header_skipped) {
            header_skipped = true;
            continue; // header line
        }
        if (line.empty())
            continue;
        if (line.size() < 40)
            continue;

        std::string ssid, bssid, rssi, channel, security;
        std::istringstream ls(line);
        std::string token;
        std::vector<std::string> tokens;
        while (ls >> token)
            tokens.push_back(token);

        if (tokens.size() >= 7) {
            security = tokens.back();
            std::size_t sec_start = tokens.size() - 1;
            while (sec_start > 0 && (tokens[sec_start - 1].find("WPA") != std::string::npos ||
                                     tokens[sec_start - 1].find("WEP") != std::string::npos ||
                                     tokens[sec_start - 1] == "--")) {
                security = tokens[sec_start - 1] + " " + security;
                --sec_start;
            }
            if (sec_start >= 6) {
                channel = tokens[sec_start - 3];
                rssi = tokens[sec_start - 4];
                bssid = tokens[sec_start - 5];
                ssid = tokens[0];
                for (std::size_t k = 1; k < sec_start - 5; ++k) {
                    ssid += " " + tokens[k];
                }
            }
        }

        if (ssid.empty())
            ssid = "<hidden>";
        if (security.empty())
            security = "Open";

        WifiNetworkRow row;
        row.ssid = ssid;
        row.signal = rssi.empty() ? "0" : rssi;
        row.security = security;
        row.channel = channel.empty() ? "0" : channel;
        row.bssid = bssid.empty() ? "-" : bssid;
        rows.push_back(std::move(row));
    }
    return rows;
}

// Parses `system_profiler SPAirPortDataType -detailLevel basic` output's
// "Other Local Wi-Fi Networks:" section into rows. A straight move of the
// plugin's existing indented-section state machine, unchanged from today.
// A network is only emitted once a non-empty SSID has been seen (matches
// the original `flush()`'s early return on an empty ssid), so malformed or
// header-only input yields an empty vector rather than a garbage row.
inline std::vector<WifiNetworkRow> parse_system_profiler_wifi(std::string_view raw) {
    std::vector<WifiNetworkRow> rows;
    if (raw.empty())
        return rows;
    std::istringstream ss{std::string{raw}};
    std::string line;
    bool in_others = false;
    std::string ssid, channel, rssi, security;
    auto flush = [&]() {
        if (ssid.empty())
            return;
        WifiNetworkRow row;
        row.ssid = ssid;
        row.signal = rssi.empty() ? "0" : rssi;
        row.security = security.empty() ? "Unknown" : security;
        row.channel = channel.empty() ? "0" : channel;
        row.bssid = "-";
        rows.push_back(std::move(row));
        ssid.clear();
        channel.clear();
        rssi.clear();
        security.clear();
    };
    while (std::getline(ss, line)) {
        if (line.find("Other Local Wi-Fi Networks:") != std::string::npos) {
            in_others = true;
            continue;
        }
        if (!in_others)
            continue;
        if (line.size() > 14 && line.substr(0, 14) == "              " && line[14] != ' ' &&
            line.back() == ':') {
            flush();
            ssid = line.substr(14, line.size() - 15);
            continue;
        }
        auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        std::string key = line.substr(0, colon);
        std::string val = line.substr(colon + 1);
        while (!key.empty() && key.front() == ' ')
            key.erase(0, 1);
        while (!val.empty() && val.front() == ' ')
            val.erase(0, 1);
        if (key == "Channel")
            channel = val;
        else if (key == "Signal / Noise")
            rssi = val;
        else if (key == "Security")
            security = val;
    }
    flush();
    return rows;
}

// ── NetworkManager D-Bus AP-tuple -> record helpers (pure, no sd-bus;
// fixture-testable without a bus connection) ────────────────────────────

// Raw property values as read off one org.freedesktop.NetworkManager.
// AccessPoint object, already unwrapped from their sd-bus variants by the
// caller (wifi_plugin.cpp). `ssid_bytes` is the RAW Ssid 'ay' payload, NOT
// UTF-8 validated -- see ssid_bytes_to_display.
struct NmAccessPointProps {
    std::vector<std::uint8_t> ssid_bytes; // Ssid, 'v'->'ay'
    std::uint8_t strength = 0;            // Strength, 'v'->'y' (percent)
    std::string hw_address;               // HwAddress, 'v'->'s'
    std::uint32_t frequency_mhz = 0;      // Frequency, 'v'->'u' (MHz)
    std::uint32_t wpa_flags = 0;          // WpaFlags, 'v'->'u'
    std::uint32_t rsn_flags = 0;          // RsnFlags, 'v'->'u'
};

namespace detail {
// Validates `bytes` as UTF-8 with no C0 control characters (a printable
// SSID). Overlong encodings, surrogate codepoints, and truncated sequences
// all fail -- deliberately conservative, since anything it accepts is
// embedded verbatim into a pipe-delimited output field (post-sof()).
inline bool is_valid_utf8_printable(const std::vector<std::uint8_t>& bytes) {
    std::size_t i = 0;
    while (i < bytes.size()) {
        const std::uint8_t c = bytes[i];
        if (c < 0x80) {
            if (c < 0x20 || c == 0x7f)
                return false; // C0 control / DEL
            ++i;
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= bytes.size() || (bytes[i + 1] & 0xC0) != 0x80)
                return false;
            const std::uint32_t cp = (static_cast<std::uint32_t>(c & 0x1F) << 6) |
                                     (bytes[i + 1] & 0x3F);
            if (cp < 0x80)
                return false; // overlong
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= bytes.size() || (bytes[i + 1] & 0xC0) != 0x80 ||
                (bytes[i + 2] & 0xC0) != 0x80)
                return false;
            const std::uint32_t cp = (static_cast<std::uint32_t>(c & 0x0F) << 12) |
                                     (static_cast<std::uint32_t>(bytes[i + 1] & 0x3F) << 6) |
                                     (bytes[i + 2] & 0x3F);
            if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))
                return false; // overlong or surrogate
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= bytes.size() || (bytes[i + 1] & 0xC0) != 0x80 ||
                (bytes[i + 2] & 0xC0) != 0x80 || (bytes[i + 3] & 0xC0) != 0x80)
                return false;
            const std::uint32_t cp = (static_cast<std::uint32_t>(c & 0x07) << 18) |
                                     (static_cast<std::uint32_t>(bytes[i + 1] & 0x3F) << 12) |
                                     (static_cast<std::uint32_t>(bytes[i + 2] & 0x3F) << 6) |
                                     (bytes[i + 3] & 0x3F);
            if (cp < 0x10000 || cp > 0x10FFFF)
                return false; // overlong or out of range
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}
} // namespace detail

// Converts a raw Ssid 'ay' byte vector to a display string: empty -> the
// same "<hidden>" marker the nmcli/airport legs use; valid printable UTF-8
// passes through as-is; anything else (a binary or non-printable SSID is
// legal 802.11) becomes a lossless `<hex:...>` marker rather than mangling
// raw bytes into the pipe-delimited record.
inline std::string ssid_bytes_to_display(const std::vector<std::uint8_t>& ssid_bytes) {
    if (ssid_bytes.empty())
        return "<hidden>";
    if (detail::is_valid_utf8_printable(ssid_bytes))
        return std::string(ssid_bytes.begin(), ssid_bytes.end());
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string hex = "<hex:";
    hex.reserve(5 + ssid_bytes.size() * 2 + 1);
    for (auto b : ssid_bytes) {
        hex += kHexDigits[(b >> 4) & 0xF];
        hex += kHexDigits[b & 0xF];
    }
    hex += '>';
    return hex;
}

// 2.4GHz / 5GHz / 6GHz centre frequency (MHz) -> 802.11 channel number,
// same mapping nmcli's own CHAN column encodes. Returns "0" when the
// frequency doesn't land on a known band/step -- never fabricates a
// channel number for an unrecognised value.
inline std::string frequency_to_channel(std::uint32_t frequency_mhz) {
    if (frequency_mhz == 2484)
        return "14"; // 2.4GHz channel 14 (Japan-only; off the regular 5MHz grid)
    if (frequency_mhz >= 2412 && frequency_mhz <= 2472 && (frequency_mhz - 2407) % 5 == 0)
        return std::to_string((frequency_mhz - 2407) / 5); // 2.4GHz channels 1-13
    if (frequency_mhz == 5935)
        return "2"; // 6GHz preferred-scanning-channel edge case (not on the 5955+ grid)
    if (frequency_mhz >= 5955 && frequency_mhz <= 7115 && (frequency_mhz - 5950) % 5 == 0)
        return std::to_string((frequency_mhz - 5950) / 5); // 6GHz
    if (frequency_mhz >= 5000 && frequency_mhz <= 5895 && (frequency_mhz - 5000) % 5 == 0)
        return std::to_string((frequency_mhz - 5000) / 5); // 5GHz
    return "0";
}

// NM80211ApSecurityFlags WpaFlags/RsnFlags -> the plugin's SECURITY column
// vocabulary. The bit values below are transcribed from NetworkManager's own
// shipped `libnm/nm-dbus-interface.h` (NM 1.52), not inferred.
//
// Ordering is most-specific-first, and deliberately matches what the nmcli
// rung-2 fallback prints in the same column, so a host that degrades from
// D-Bus to nmcli does not silently change an AP's reported security:
//   802.1X (enterprise, either flag word) > SAE/WPA3 > OWE > WPA2 > WPA1 > NONE.
//
// Known limit, unchanged: this cannot distinguish a WEP-only AP from a
// genuinely open one -- WEP is signalled by the AP's `Flags`/PRIVACY bit, a
// property this plugin does not read (out of the spec's requested property
// list). An open AP and a WEP AP both report NONE.
inline std::string nm_security_flags_to_string(std::uint32_t wpa_flags, std::uint32_t rsn_flags) {
    constexpr std::uint32_t kKeyMgmt8021X = 0x200; // NM_802_11_AP_SEC_KEY_MGMT_802_1X
    constexpr std::uint32_t kKeyMgmtSae = 0x400;   // NM_802_11_AP_SEC_KEY_MGMT_SAE (WPA3-Personal)
    constexpr std::uint32_t kKeyMgmtOwe = 0x800;   // NM_802_11_AP_SEC_KEY_MGMT_OWE (enhanced open)
    const std::uint32_t either = wpa_flags | rsn_flags;
    if ((either & kKeyMgmt8021X) != 0)
        return "802.1X";
    // Without this, a WPA3-Personal AP reported as "WPA2" -- a security
    // downgrade in the operator's own audit view, and a disagreement with
    // the nmcli leg, which prints WPA3.
    if ((either & kKeyMgmtSae) != 0)
        return "WPA3";
    if ((either & kKeyMgmtOwe) != 0)
        return "OWE";
    if (rsn_flags != 0)
        return "WPA2";
    if (wpa_flags != 0)
        return "WPA1";
    return "NONE";
}

// Assembles a list_networks row from one AP's raw properties, applying the
// same "<hidden>"/"-" defaults the nmcli/airport legs use so all three
// list_networks sources emit byte-compatible records.
inline WifiNetworkRow nm_ap_to_row(const NmAccessPointProps& ap) {
    WifiNetworkRow row;
    row.ssid = ssid_bytes_to_display(ap.ssid_bytes);
    row.signal = std::to_string(ap.strength);
    row.security = nm_security_flags_to_string(ap.wpa_flags, ap.rsn_flags);
    row.channel = frequency_to_channel(ap.frequency_mhz);
    row.bssid = ap.hw_address.empty() ? "-" : ap.hw_address;
    return row;
}

// Assembles a connected row from the active AP's raw properties plus the
// owning device's Interface name. `interface_name` fills the column nmcli's
// leg sources from GENERAL.CONNECTION (the connection profile's display
// name) -- the D-Bus leg uses the device's Interface property instead
// (e.g. "wlan0"), a deliberate scope decision: the spec's D-Bus property
// list for `connected` never named an ActiveConnection/Id hop, and adding
// one would grow the bounded call sequence beyond what's in the
// type-signature table. See the package report's deviations section.
inline WifiConnectedRow nm_ap_to_connected_row(const NmAccessPointProps& ap,
                                               const std::string& interface_name) {
    WifiConnectedRow row;
    row.ssid = ssid_bytes_to_display(ap.ssid_bytes);
    row.signal = std::to_string(ap.strength);
    row.security = nm_security_flags_to_string(ap.wpa_flags, ap.rsn_flags);
    row.bssid = ap.hw_address.empty() ? "-" : ap.hw_address;
    row.connection = interface_name.empty() ? "-" : interface_name;
    return row;
}

} // namespace yuzu::wifi
