/**
 * test_bitlocker_windows_wmi.cpp — bitlocker_windows_wmi.hpp (Wave-3
 * native-acquisition migration: Win32_EncryptableVolume WMI query +
 * GetConversionStatus() method call, replacing the raw `manage-bde
 * -status` popen).
 *
 * Portable and unguarded — the header takes plain
 * std::map<std::string, std::string> rows with no COM/<windows.h>
 * dependency, so this TU carries no platform guard and runs on every leg,
 * macOS included. That is deliberate: this is the only part of the
 * Windows WMI path that can be verified off-Windows, mirroring
 * test_discovery_parsers.cpp's format_mac48 precedent and
 * test_users_win_events.cpp's host-agnostic wevtapi-shape parser tests.
 * Fixture rows are synthetic (constructed to the documented WMI property
 * shapes), not a live capture — there is no portable way to run a real WMI
 * query from this suite.
 */
#include "bitlocker_windows_wmi.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::bitlocker::windows;

TEST_CASE("protection_status_text maps the documented ProtectionStatus enum",
          "[agent][bitlocker_windows_wmi]") {
    CHECK(protection_status_text("0") == "Protection Off");
    CHECK(protection_status_text("1") == "Protection On");
    CHECK(protection_status_text("2") == "Protection Unknown");
    CHECK(protection_status_text("") == "Protection Unknown");
    CHECK(protection_status_text("garbage") == "Protection Unknown");
}

TEST_CASE("conversion_status_text maps the documented ConversionStatus enum",
          "[agent][bitlocker_windows_wmi]") {
    CHECK(conversion_status_text("0") == "Fully Decrypted");
    CHECK(conversion_status_text("1") == "Fully Encrypted");
    CHECK(conversion_status_text("2") == "Encryption In Progress");
    CHECK(conversion_status_text("3") == "Decryption In Progress");
    CHECK(conversion_status_text("4") == "Encryption Paused");
    CHECK(conversion_status_text("5") == "Decryption Paused");
    CHECK(conversion_status_text("6") == "Unknown");
    CHECK(conversion_status_text("") == "Unknown");
}

TEST_CASE("format_percentage renders a plain integer with a trailing percent sign",
          "[agent][bitlocker_windows_wmi]") {
    CHECK(format_percentage("100") == "100%");
    CHECK(format_percentage("0") == "0%");
    CHECK(format_percentage("57") == "57%");
}

TEST_CASE("format_percentage reports unknown rather than fabricating a value",
          "[agent][bitlocker_windows_wmi]") {
    CHECK(format_percentage("") == "unknown");
    CHECK(format_percentage("N/A") == "unknown");
    CHECK(format_percentage("-1") == "unknown"); // '-' is not a digit — never a fabricated percent
    CHECK(format_percentage("50.5") == "unknown");
}

TEST_CASE("parse_encryptable_volumes maps a full WMI row", "[agent][bitlocker_windows_wmi]") {
    std::vector<WmiRow> rows = {
        {{"DeviceID", R"(\\?\Volume{7263f4b6-1234-5678-9abc-def012345678}\)"},
         {"DriveLetter", "C:"},
         {"ProtectionStatus", "1"}},
    };
    auto volumes = parse_encryptable_volumes(rows);
    REQUIRE(volumes.size() == 1);
    CHECK(volumes[0].device_id == R"(\\?\Volume{7263f4b6-1234-5678-9abc-def012345678}\)");
    CHECK(volumes[0].drive_letter == "C:");
    CHECK(volumes[0].protection_status_raw == "1");
}

TEST_CASE("parse_encryptable_volumes drops a row missing DeviceID",
          "[agent][bitlocker_windows_wmi]") {
    std::vector<WmiRow> rows = {
        {{"DriveLetter", "D:"}, {"ProtectionStatus", "0"}},
        {{"DeviceID", ""}, {"DriveLetter", "E:"}, {"ProtectionStatus", "0"}},
    };
    CHECK(parse_encryptable_volumes(rows).empty());
}

TEST_CASE("parse_encryptable_volumes tolerates a row missing DriveLetter/ProtectionStatus",
          "[agent][bitlocker_windows_wmi]") {
    std::vector<WmiRow> rows = {
        {{"DeviceID", R"(\\?\Volume{aaaaaaaa-0000-0000-0000-000000000000}\)"}},
    };
    auto volumes = parse_encryptable_volumes(rows);
    REQUIRE(volumes.size() == 1);
    CHECK(volumes[0].drive_letter.empty());
    CHECK(volumes[0].protection_status_raw.empty());
}

TEST_CASE("build_volume_object_path doubles every backslash for the WQL string literal",
          "[agent][bitlocker_windows_wmi]") {
    auto path = build_volume_object_path(R"(\\?\Volume{GUID}\)");
    CHECK(path == R"(Win32_EncryptableVolume.DeviceID="\\\\?\\Volume{GUID}\\")");
}

TEST_CASE("parse_conversion_status decodes a full method-call result row",
          "[agent][bitlocker_windows_wmi]") {
    WmiRow row = {{"ReturnValue", "0"}, {"ConversionStatus", "1"}, {"EncryptionPercentage", "100"}};
    auto state = parse_conversion_status(row);
    CHECK(state.conversion_text == "Fully Encrypted");
    CHECK(state.percent_text == "100%");
}

TEST_CASE("parse_conversion_status degrades honestly when fields are absent",
          "[agent][bitlocker_windows_wmi]") {
    WmiRow empty_row;
    auto state = parse_conversion_status(empty_row);
    CHECK(state.conversion_text == "Unknown");
    CHECK(state.percent_text == "unknown");
}

TEST_CASE("parse_conversion_status rejects a non-zero method ReturnValue",
          "[agent][bitlocker_windows_wmi]") {
    // The WMI method call transported successfully (COM layer OK) but
    // BitLocker's own method failed — out params must not be trusted even
    // though ConversionStatus/EncryptionPercentage are present and well-formed.
    WmiRow row = {{"ReturnValue", "2150694912"}, {"ConversionStatus", "0"},
                  {"EncryptionPercentage", "0"}};
    auto state = parse_conversion_status(row);
    CHECK(state.conversion_text == "Unknown");
    CHECK(state.percent_text == "unknown");
}

TEST_CASE("format_volume_row assembles the frozen 5-field shape, method always unknown",
          "[agent][bitlocker_windows_wmi]") {
    EncryptableVolume vol;
    vol.drive_letter = "C:";
    vol.protection_status_raw = "1";
    ConversionState conv{"Fully Encrypted", "100%"};
    CHECK(format_volume_row(vol, conv) == "volume|C:|Fully Encrypted|100%|unknown|Protection On");
}

TEST_CASE("format_volume_row falls back to unknown for a missing drive letter",
          "[agent][bitlocker_windows_wmi]") {
    EncryptableVolume vol; // drive_letter left empty
    ConversionState conv{"Unknown", "unknown"};
    CHECK(format_volume_row(vol, conv) == "volume|unknown|Unknown|unknown|unknown|Protection Unknown");
}

TEST_CASE("is_permission_denied recognizes the E_ACCESSDENIED phrasings",
          "[agent][bitlocker_windows_wmi]") {
    CHECK(is_permission_denied(std::optional<std::string>{"Access is denied."}));
    CHECK(is_permission_denied(std::optional<std::string>{"ACCESS DENIED"}));
    CHECK(is_permission_denied(std::optional<std::string>{"WMI call failed: 0x80070005"}));
}

TEST_CASE("is_permission_denied is false for an unrelated error or no error",
          "[agent][bitlocker_windows_wmi]") {
    CHECK_FALSE(is_permission_denied(std::optional<std::string>{"RPC server unavailable"}));
    CHECK_FALSE(is_permission_denied(std::nullopt));
}
