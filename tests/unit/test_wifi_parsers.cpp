/**
 * test_wifi_parsers.cpp — pure wifi parse/format helpers (wifi_parsers.hpp,
 * PKG-WIFI).
 *
 * The bounded argv runner (nmcli/iw/iwlist/iwconfig/airport/
 * system_profiler) and the bounded sd-bus NetworkManager session are the
 * impure shells, both living in wifi_plugin.cpp; every parser/formatter
 * here is header-pure and pinned on every host regardless of platform or
 * libsystemd availability (the netprobe_stats.hpp / firewall_parsers.hpp
 * pattern).
 *
 * None of the fixtures below are a literal capture from a live host (no
 * Linux/NetworkManager/nmcli/iw host was available while writing this
 * package) -- they are hand-constructed but format-accurate, built from the
 * documented nmcli -t / iwconfig / airport -s / system_profiler column
 * layouts and the published NetworkManager D-Bus property types, the same
 * disclosure services_parsers.hpp's own fixtures carry.
 */

#include "wifi_parsers.hpp"

// wifi_parsers.hpp stays pure (wifi_tool_answered is a template over the
// result's own termination_reason type, so the header takes no runner
// dependency). The TEST pulls the real enum in deliberately, so a rename or
// a reordering of TerminationReason breaks here rather than silently
// re-tuning the honest-degradation decision against a local copy.
#include <yuzu/agent/subprocess_runner.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::wifi;

// ── split_nmcli_terse_line / parse_nmcli_wifi_list ─────────────────────

TEST_CASE("wifi: split_nmcli_terse_line honours backslash-escaped colons", "[wifi]") {
    auto fields = split_nmcli_terse_line(R"(My\:Network:80:WPA2:6:AA\:BB\:CC\:DD\:EE\:FF)");
    REQUIRE(fields.size() == 5);
    CHECK(fields[0] == "My:Network"); // escaped colon unescaped, real separator kept
    CHECK(fields[1] == "80");
    CHECK(fields[2] == "WPA2");
    CHECK(fields[3] == "6");
    CHECK(fields[4] == "AA:BB:CC:DD:EE:FF"); // every colon here was escaped
}

TEST_CASE("wifi: split_nmcli_terse_line without any escapes matches a plain split", "[wifi]") {
    auto fields = split_nmcli_terse_line("MyWifi:80:WPA2:6:AA:BB:CC:DD:EE:FF");
    REQUIRE(fields.size() == 10);
    CHECK(fields[0] == "MyWifi");
    CHECK(fields[9] == "FF");
}

TEST_CASE("wifi: split_nmcli_terse_line keeps a trailing lone backslash literal", "[wifi]") {
    auto fields = split_nmcli_terse_line(R"(abc\)");
    REQUIRE(fields.size() == 1);
    CHECK(fields[0] == "abc\\");
}

TEST_CASE("wifi: parse_nmcli_wifi_list on empty input yields no rows", "[wifi]") {
    CHECK(parse_nmcli_wifi_list("").empty());
}

TEST_CASE("wifi: parse_nmcli_wifi_list — ordinary rows", "[wifi]") {
    // A real nmcli -t escapes ':' inside every field value, BSSID included
    // (its own colons would otherwise be misread as column separators).
    auto rows = parse_nmcli_wifi_list(
        R"(HomeNet:78:WPA2:6:AA\:BB\:CC\:DD\:EE\:FF)" "\n"
        R"(Guest:45:--:11:11\:22\:33\:44\:55\:66)" "\n");
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].ssid == "HomeNet");
    CHECK(rows[0].signal == "78");
    CHECK(rows[0].security == "WPA2");
    CHECK(rows[0].channel == "6");
    CHECK(rows[0].bssid == "AA:BB:CC:DD:EE:FF");
    CHECK(rows[1].security == "--");
    CHECK(rows[1].bssid == "11:22:33:44:55:66");
}

TEST_CASE("wifi: parse_nmcli_wifi_list — escaped-colon SSID stays intact", "[wifi]") {
    // A real nmcli -t escapes ':' inside a field value; an SSID literally
    // named "Coffee:Shop" is emitted as "Coffee\:Shop" in the SSID column.
    auto rows = parse_nmcli_wifi_list(R"(Coffee\:Shop:60:WPA2:1:AA\:BB\:CC\:DD\:EE\:FF)");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].ssid == "Coffee:Shop");
    CHECK(rows[0].signal == "60");
    CHECK(rows[0].security == "WPA2");
    CHECK(rows[0].bssid == "AA:BB:CC:DD:EE:FF");
}

TEST_CASE("wifi: parse_nmcli_wifi_list — missing trailing fields default honestly", "[wifi]") {
    auto rows = parse_nmcli_wifi_list(":::::\n::::\n");
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].ssid == "<hidden>");
    CHECK(rows[0].security == "Open");
    CHECK(rows[0].signal == "0");
    CHECK(rows[0].channel == "0");
    CHECK(rows[0].bssid == "-");
    // A line short even of the trailing bssid column defaults the same way.
    CHECK(rows[1].bssid == "-");
}

TEST_CASE("wifi: parse_nmcli_wifi_list — blank lines are skipped", "[wifi]") {
    auto rows = parse_nmcli_wifi_list("HomeNet:78:WPA2:6:AA\n\n\nGuest:45:Open:1:BB\n");
    CHECK(rows.size() == 2);
}

// ── parse_nmcli_device_show ─────────────────────────────────────────────

TEST_CASE("wifi: parse_nmcli_device_show — a connected device", "[wifi]") {
    auto row = parse_nmcli_device_show(
        "GENERAL.CONNECTION:Home WiFi\n"
        "WIFI.SSID:HomeNet\n"
        "WIFI.SIGNAL:82\n"
        "WIFI.SECURITY:WPA2\n"
        "WIFI.BSSID:AA:BB:CC:DD:EE:FF\n");
    REQUIRE(row.has_value());
    CHECK(row->ssid == "HomeNet");
    CHECK(row->signal == "82");
    CHECK(row->security == "WPA2");
    CHECK(row->bssid == "AA:BB:CC:DD:EE:FF");
    CHECK(row->connection == "Home WiFi");
}

TEST_CASE("wifi: parse_nmcli_device_show — no WIFI.SSID means not connected", "[wifi]") {
    auto row = parse_nmcli_device_show("GENERAL.CONNECTION:--\nWIFI.SSID:\n");
    CHECK_FALSE(row.has_value());
}

TEST_CASE("wifi: parse_nmcli_device_show — missing optional fields default honestly", "[wifi]") {
    auto row = parse_nmcli_device_show("WIFI.SSID:HomeNet\n");
    REQUIRE(row.has_value());
    CHECK(row->signal == "0");
    CHECK(row->security == "Open");
    CHECK(row->bssid == "-");
    CHECK(row->connection == "-");
}

TEST_CASE("wifi: parse_nmcli_device_show on empty input", "[wifi]") {
    CHECK_FALSE(parse_nmcli_device_show("").has_value());
}

// ── iw / iwlist / iwconfig text filtering ───────────────────────────────

TEST_CASE("wifi: parse_iw_dev_interfaces extracts the interface token", "[wifi]") {
    auto ifaces = parse_iw_dev_interfaces(
        "phy#0\n"
        "\tInterface wlan0\n"
        "\t\tifindex 3\n"
        "\t\taddr aa:bb:cc:dd:ee:ff\n");
    REQUIRE(ifaces.size() == 1);
    CHECK(ifaces[0] == "wlan0");
}

TEST_CASE("wifi: parse_iw_dev_interfaces on output with no interfaces", "[wifi]") {
    CHECK(parse_iw_dev_interfaces("phy#0\n\t\tifindex 3\n").empty());
}

TEST_CASE("wifi: filter_iwlist_scan_lines keeps only ESSID/Quality/Encryption lines",
          "[wifi]") {
    auto out = filter_iwlist_scan_lines(
        "wlan0     Scan completed :\n"
        "          Cell 01 - Address: AA:BB:CC:DD:EE:FF\n"
        "                    ESSID:\"HomeNet\"\n"
        "                    Quality=70/70  Signal level=-40 dBm\n"
        "                    Encryption key:on\n"
        "                    Bit Rates:1 Mb/s\n");
    CHECK(out.find("ESSID:\"HomeNet\"") != std::string::npos);
    CHECK(out.find("Quality=70/70") != std::string::npos);
    CHECK(out.find("Encryption key:on") != std::string::npos);
    CHECK(out.find("Bit Rates") == std::string::npos);
    CHECK(out.find("Scan completed") == std::string::npos);
}

TEST_CASE("wifi: filter_iwconfig_essid_signal_lines keeps only ESSID/Signal lines", "[wifi]") {
    auto out = filter_iwconfig_essid_signal_lines(
        "wlan0     IEEE 802.11  ESSID:\"HomeNet\"\n"
        "          Mode:Managed  Frequency:2.437 GHz\n"
        "          Signal level=-45 dBm\n");
    CHECK(out.find("ESSID:\"HomeNet\"") != std::string::npos);
    CHECK(out.find("Signal level=-45 dBm") != std::string::npos);
    CHECK(out.find("Mode:Managed") == std::string::npos);
}

TEST_CASE("wifi: parse_iwconfig_essid_blob — associated blob passes through", "[wifi]") {
    auto blob = parse_iwconfig_essid_blob("ESSID:\"HomeNet\"\nSignal level=-45 dBm");
    REQUIRE(blob.has_value());
    CHECK(blob->find("HomeNet") != std::string::npos);
}

TEST_CASE("wifi: parse_iwconfig_essid_blob — ESSID:off means not connected", "[wifi]") {
    CHECK_FALSE(parse_iwconfig_essid_blob("wlan0     ESSID:off/any").has_value());
}

TEST_CASE("wifi: parse_iwconfig_essid_blob on empty input", "[wifi]") {
    CHECK_FALSE(parse_iwconfig_essid_blob("").has_value());
}

// ── macOS airport / system_profiler parsing ─────────────────────────────

TEST_CASE("wifi: parse_airport_scan on empty input yields no rows", "[wifi]") {
    CHECK(parse_airport_scan("").empty());
}

TEST_CASE("wifi: parse_airport_scan parses a fixed-width row", "[wifi]") {
    // Header line, then one network row: SSID BSSID RSSI CHANNEL HT CC SECURITY.
    std::string blob =
        "                            SSID BSSID             RSSI CHANNEL HT CC SECURITY\n"
        "                         HomeNet aa:bb:cc:dd:ee:ff  -40       6  Y  US WPA2(PSK/AES/AES)\n";
    auto rows = parse_airport_scan(blob);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].ssid == "HomeNet");
    CHECK(rows[0].bssid == "aa:bb:cc:dd:ee:ff");
    CHECK(rows[0].signal == "-40");
    CHECK(rows[0].channel == "6");
}

TEST_CASE("wifi: parse_system_profiler_wifi extracts networks under the section header",
          "[wifi]") {
    // Network-name lines sit at exactly 14 leading spaces in real
    // system_profiler output -- the indent the parser's fixed-column check
    // requires (see the "              " (14-space) literal in
    // wifi_parsers.hpp's parse_system_profiler_wifi).
    std::string blob =
        "      Other Local Wi-Fi Networks:\n"
        "              HomeNet:\n"
        "                  Channel: 6\n"
        "                  Signal / Noise: -40 dBm / -90 dBm\n"
        "                  Security: WPA2 Personal\n"
        "              Guest:\n"
        "                  Channel: 11\n"
        "                  Signal / Noise: -60 dBm / -90 dBm\n";
    auto rows = parse_system_profiler_wifi(blob);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].ssid == "HomeNet");
    CHECK(rows[0].channel == "6");
    CHECK(rows[0].signal == "-40 dBm / -90 dBm");
    CHECK(rows[0].security == "WPA2 Personal");
    CHECK(rows[1].ssid == "Guest");
    CHECK(rows[1].security == "Unknown"); // no Security line for this entry
}

TEST_CASE("wifi: parse_system_profiler_wifi with no section header yields no rows", "[wifi]") {
    CHECK(parse_system_profiler_wifi("Wi-Fi:\n    Card Type: AirPort\n").empty());
}

// ── NetworkManager D-Bus AP-tuple -> record helpers ─────────────────────

TEST_CASE("wifi: ssid_bytes_to_display — empty means hidden", "[wifi]") {
    CHECK(ssid_bytes_to_display({}) == "<hidden>");
}

TEST_CASE("wifi: ssid_bytes_to_display — valid printable UTF-8 passes through", "[wifi]") {
    std::vector<std::uint8_t> bytes = {'H', 'o', 'm', 'e', 0xC3, 0xA9}; // "Home" + U+00E9 (é)
    CHECK(ssid_bytes_to_display(bytes) == "Home\xC3\xA9");
}

TEST_CASE("wifi: ssid_bytes_to_display — non-UTF8/non-printable becomes a hex marker",
          "[wifi]") {
    std::vector<std::uint8_t> bytes = {0xFF, 0x00, 0x01, 0xC0, 0x80};
    auto out = ssid_bytes_to_display(bytes);
    CHECK(out == "<hex:ff0001c080>");
}

TEST_CASE("wifi: ssid_bytes_to_display — a C0 control byte is rejected as printable",
          "[wifi]") {
    std::vector<std::uint8_t> bytes = {'a', 'b', 0x07, 'c'}; // embedded BEL
    auto out = ssid_bytes_to_display(bytes);
    CHECK(out == "<hex:61620763>");
}

TEST_CASE("wifi: frequency_to_channel — 2.4GHz band", "[wifi]") {
    CHECK(frequency_to_channel(2412) == "1");
    CHECK(frequency_to_channel(2437) == "6");
    CHECK(frequency_to_channel(2472) == "13");
    CHECK(frequency_to_channel(2484) == "14");
}

TEST_CASE("wifi: frequency_to_channel — 5GHz and 6GHz bands", "[wifi]") {
    CHECK(frequency_to_channel(5180) == "36");
    CHECK(frequency_to_channel(5955) == "1");
    CHECK(frequency_to_channel(5935) == "2");
}

TEST_CASE("wifi: frequency_to_channel — unrecognised frequency is honestly 0", "[wifi]") {
    CHECK(frequency_to_channel(0) == "0");
    CHECK(frequency_to_channel(999999) == "0");
    CHECK(frequency_to_channel(2413) == "0"); // off the 5MHz grid
}

// "Open", not "NONE": the nmcli, airport and system_profiler legs all render
// an unsecured AP as "Open". If the D-Bus leg disagreed, the SAME access point
// would change its reported security string purely because the host degraded
// from D-Bus to nmcli.
TEST_CASE("wifi: nm_security_flags_to_string — open network matches the nmcli vocabulary",
          "[wifi]") {
    CHECK(nm_security_flags_to_string(0, 0) == "Open");
    // Pin the cross-rung agreement directly: same AP, both acquisition paths.
    auto nmcli_rows = parse_nmcli_wifi_list("OpenNet:70::6:AA");
    REQUIRE(nmcli_rows.size() == 1);
    CHECK(nmcli_rows[0].security == nm_security_flags_to_string(0, 0));
}

TEST_CASE("wifi: nm_security_flags_to_string — WPA1 only", "[wifi]") {
    CHECK(nm_security_flags_to_string(0x100, 0) == "WPA1");
}

TEST_CASE("wifi: nm_security_flags_to_string — WPA2 (non-zero RsnFlags)", "[wifi]") {
    CHECK(nm_security_flags_to_string(0x100, 0x100) == "WPA2");
}

TEST_CASE("wifi: nm_security_flags_to_string — 802.1X takes priority", "[wifi]") {
    CHECK(nm_security_flags_to_string(0x200, 0) == "802.1X");
    CHECK(nm_security_flags_to_string(0, 0x300) == "802.1X");
}

// Bit values transcribed from NetworkManager's shipped libnm/nm-dbus-interface.h
// (NM 1.52): SAE = 0x400, OWE = 0x800. Before this, a WPA3-Personal AP was
// reported as "WPA2" -- a security downgrade in the operator's audit view and a
// disagreement with the nmcli rung-2 fallback, which prints WPA3.
TEST_CASE("wifi: nm_security_flags_to_string — WPA3/SAE is not reported as WPA2", "[wifi]") {
    // RSN word carrying PSK+SAE, as a WPA2/WPA3 transition-mode AP advertises.
    CHECK(nm_security_flags_to_string(0, 0x400) == "WPA3");
    CHECK(nm_security_flags_to_string(0, 0x100 | 0x400) == "WPA3");
    // Enterprise still outranks SAE (WPA3-Enterprise reports 802.1X).
    CHECK(nm_security_flags_to_string(0, 0x200 | 0x400) == "802.1X");
}

TEST_CASE("wifi: nm_security_flags_to_string — OWE enhanced-open is distinct from open",
          "[wifi]") {
    CHECK(nm_security_flags_to_string(0, 0x800) == "OWE");
    // OWE transition mode (0x1000) must not fall through to the bare
    // "non-zero RsnFlags implies WPA2" branch.
    CHECK(nm_security_flags_to_string(0, 0x1000) == "OWE");
    // ...and a genuinely open AP is still Open, not OWE.
    CHECK(nm_security_flags_to_string(0, 0) == "Open");
}

// ── honest degradation: a failed query is never a negative answer ──────────
//
// Regression guard for the fabricated-success class that shipped twice in
// Wave 3. `classify_runner_failure` deliberately returns nullopt for a normal
// exit, so a nonzero-exiting nmcli/iwconfig is invisible to the ABI status
// seam; without wifi_tool_answered(), `connected` reported a confident
// "Not connected" when in fact nothing had been determined.
namespace {
struct FakeResult {
    yuzu::agent::TerminationReason termination_reason =
        yuzu::agent::TerminationReason::exited;
    int exit_code = 0;
};
} // namespace

TEST_CASE("wifi: wifi_tool_answered — only a clean successful exit answers the question",
          "[wifi]") {
    using TR = yuzu::agent::TerminationReason;

    // The one outcome that is a real answer.
    CHECK(wifi_tool_answered(FakeResult{TR::exited, 0}).answered);

    // A tool that ran but FAILED has told us nothing -- this is the exact
    // case that produced a fabricated "Not connected".
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::exited, 1}).answered);
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::exited, 7}).answered);
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::exited, 127}).answered);

    // Nor has a tool that never ran, was killed, or timed out.
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::spawn_error, -1}).answered);
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::deadline, -1}).answered);
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::cancelled, -1}).answered);
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::signaled, -1}).answered);
    CHECK_FALSE(wifi_tool_answered(FakeResult{TR::line_limit, -1}).answered);
}

TEST_CASE("wifi: nm_ap_to_row assembles a list_networks row from raw AP properties",
          "[wifi]") {
    NmAccessPointProps ap;
    ap.ssid_bytes = {'H', 'o', 'm', 'e', 'N', 'e', 't'};
    ap.strength = 82;
    ap.hw_address = "AA:BB:CC:DD:EE:FF";
    ap.frequency_mhz = 2437;
    ap.wpa_flags = 0x100;
    ap.rsn_flags = 0x100;

    auto row = nm_ap_to_row(ap);
    CHECK(row.ssid == "HomeNet");
    CHECK(row.signal == "82");
    CHECK(row.security == "WPA2");
    CHECK(row.channel == "6");
    CHECK(row.bssid == "AA:BB:CC:DD:EE:FF");
}

TEST_CASE("wifi: nm_ap_to_row — an empty HwAddress defaults to '-'", "[wifi]") {
    NmAccessPointProps ap;
    ap.ssid_bytes = {'X'};
    auto row = nm_ap_to_row(ap);
    CHECK(row.bssid == "-");
}

TEST_CASE("wifi: nm_ap_to_connected_row assembles a connected row and uses the interface name",
          "[wifi]") {
    NmAccessPointProps ap;
    ap.ssid_bytes = {'H', 'o', 'm', 'e', 'N', 'e', 't'};
    ap.strength = 90;
    ap.hw_address = "AA:BB:CC:DD:EE:FF";
    ap.wpa_flags = 0;
    ap.rsn_flags = 0x100;

    auto row = nm_ap_to_connected_row(ap, "wlan0");
    CHECK(row.ssid == "HomeNet");
    CHECK(row.signal == "90");
    CHECK(row.security == "WPA2");
    CHECK(row.bssid == "AA:BB:CC:DD:EE:FF");
    CHECK(row.connection == "wlan0");
}

TEST_CASE("wifi: nm_ap_to_connected_row — an empty interface name defaults to '-'", "[wifi]") {
    NmAccessPointProps ap;
    auto row = nm_ap_to_connected_row(ap, "");
    CHECK(row.connection == "-");
}
