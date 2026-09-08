/**
 * test_peripherals_linux_parsers.cpp — pure parser + injected-root walk
 * tests for the peripherals plugin's Linux leg
 * (peripherals_linux_parsers.hpp). Builds and runs on every OS: nothing here
 * touches a real /sys, only the fixture tree under
 * tests/unit/fixtures/wave9/peripherals/linux/sysfs_tree/ (see its
 * provenance.txt: pci/usb are REAL CAPTURE from a debian:12 container,
 * thunderbolt is a RECONSTRUCTION citing
 * Documentation/ABI/testing/sysfs-bus-thunderbolt).
 */
#include <catch2/catch_test_macros.hpp>

#include "peripherals_linux_parsers.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

std::filesystem::path fixture_root() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return std::filesystem::path(YUZU_TEST_FIXTURE_DIR) / "wave9" / "peripherals" / "linux" /
          "sysfs_tree";
#else
    return std::filesystem::path("tests/unit/fixtures/wave9/peripherals/linux/sysfs_tree");
#endif
}

bool row_starts_with(const std::string& row, std::string_view prefix) {
    return row.size() >= prefix.size() && row.compare(0, prefix.size(), prefix) == 0;
}

std::size_t count_rows_with_field(const std::vector<std::string>& rows, int field_index,
                                  std::string_view value) {
    std::size_t n = 0;
    for (const auto& row : rows) {
        std::size_t start = 0;
        int idx = 0;
        while (idx < field_index) {
            auto pos = row.find('|', start);
            REQUIRE(pos != std::string::npos);
            start = pos + 1;
            ++idx;
        }
        auto end = row.find('|', start);
        const std::string field = row.substr(start, end == std::string::npos ? end : end - start);
        if (field == value)
            ++n;
    }
    return n;
}

} // namespace

// ── pure parsers ─────────────────────────────────────────────────────────

TEST_CASE("peripherals linux: parse_hex_attr accepts 0x-prefixed and bare hex",
          "[peripherals][linux][parsers]") {
    using namespace yuzu::peripherals::lnx;
    CHECK(parse_hex_attr("0x8086") == std::optional<std::uint32_t>{0x8086});
    CHECK(parse_hex_attr("8086") == std::optional<std::uint32_t>{0x8086});
    CHECK(parse_hex_attr("0X1AF4") == std::optional<std::uint32_t>{0x1af4});
    CHECK(parse_hex_attr("  0x09\n") == std::optional<std::uint32_t>{0x09});
    CHECK_FALSE(parse_hex_attr("").has_value());
    CHECK_FALSE(parse_hex_attr("not-hex").has_value());
    CHECK_FALSE(parse_hex_attr("0x").has_value());
}

TEST_CASE("peripherals linux: parse_pci_class parses a 24-bit class code",
          "[peripherals][linux][parsers]") {
    using namespace yuzu::peripherals::lnx;
    CHECK(parse_pci_class("0x0c0330") == std::optional<std::uint32_t>{0x0c0330});
    CHECK_FALSE(parse_pci_class("garbage").has_value());
}

TEST_CASE("peripherals linux: is_usb_interface_entry keys on ':'",
          "[peripherals][linux][parsers]") {
    using namespace yuzu::peripherals::lnx;
    CHECK(is_usb_interface_entry("1-0:1.0"));
    CHECK(is_usb_interface_entry("2-1.3:1.1"));
    CHECK_FALSE(is_usb_interface_entry("usb1"));
    CHECK_FALSE(is_usb_interface_entry("1-2.1"));
}

TEST_CASE("peripherals linux: is_tb_domain_entry matches domainN only",
          "[peripherals][linux][parsers]") {
    using namespace yuzu::peripherals::lnx;
    CHECK(is_tb_domain_entry("domain0"));
    CHECK(is_tb_domain_entry("domain12"));
    CHECK_FALSE(is_tb_domain_entry("domain"));    // no digits
    CHECK_FALSE(is_tb_domain_entry("domainX"));   // non-digit suffix
    CHECK_FALSE(is_tb_domain_entry("0-0"));
    CHECK_FALSE(is_tb_domain_entry("0-0:1.1"));
}

// ── walks over the fixture tree ─────────────────────────────────────────

TEST_CASE("peripherals linux: usb_rows_at reads the root hubs, skips interfaces",
          "[peripherals][linux][walk]") {
    using namespace yuzu::peripherals::lnx;
    std::optional<std::string_view> token;
    const auto rows = usb_rows_at(fixture_root(), token);
    CHECK_FALSE(token.has_value());
    REQUIRE(rows.size() == 2); // usb1, usb2 -- "1-0:1.0"/"2-0:1.0" interfaces excluded

    for (const auto& row : rows) {
        CHECK(row_starts_with(row, "usb|"));
        CHECK(row.find(":1.0") == std::string::npos); // no interface entry leaked through
    }
    // usb1 is a hub (bDeviceClass 09) with every attribute captured.
    const bool found_usb1 =
        std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
            return r == "usb|usb1|1d6b|0002|09|00|Linux 7.0.12-linuxkit vhci_hcd|"
                        "USB/IP Virtual Host Controller|vhci_hcd.0|480|1";
        });
    CHECK(found_usb1);
    // usb2 is missing manufacturer/product/serial/speed in the fixture --
    // read_attr's ENOENT -> nullopt -> "-" fallback must fill them in, and
    // it must still be recognised as a hub from its real bDeviceClass=09.
    const bool found_usb2 = std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
        return r == "usb|usb2|1d6b|0003|09|00|-|-|-|-|1";
    });
    CHECK(found_usb2);
}

TEST_CASE("peripherals linux: pci_rows_at reads >= 10 virtio devices",
          "[peripherals][linux][walk]") {
    using namespace yuzu::peripherals::lnx;
    std::optional<std::string_view> token;
    const auto rows = pci_rows_at(fixture_root(), token);
    CHECK_FALSE(token.has_value());
    REQUIRE(rows.size() >= 10);
    for (const auto& row : rows)
        CHECK(row_starts_with(row, "pci|"));

    // field index: pci(0)|bus_path(1)|vendor(2)|device(3)|class(4)|...
    CHECK(count_rows_with_field(rows, 2, "1af4") == rows.size());

    // The two "rich" devices captured a `driver` file (the fixture
    // substitution for a symlink); every other minimal device has none and
    // must fall back to "-".
    const auto driver_rows = count_rows_with_field(rows, 7, "virtio-pci");
    CHECK(driver_rows == 2);
    const auto no_driver_rows = count_rows_with_field(rows, 7, "-");
    CHECK(no_driver_rows == rows.size() - 2);
}

TEST_CASE("peripherals linux: thunderbolt_rows_at yields one host_controller "
         "and skips the retimer",
         "[peripherals][linux][walk]") {
    using namespace yuzu::peripherals::lnx;
    std::optional<std::string_view> token;
    const auto rows = thunderbolt_rows_at(fixture_root(), token);
    CHECK_FALSE(token.has_value());
    REQUIRE(rows.size() == 3); // domain0 (host_controller) + 0-0 + 0-1 (devices); 0-0:1.1 skipped

    const auto host_controllers = count_rows_with_field(rows, 2, "host_controller");
    CHECK(host_controllers == 1);
    const auto devices = count_rows_with_field(rows, 2, "device");
    CHECK(devices == 2);

    for (const auto& row : rows)
        CHECK(row.find("Retimer") == std::string::npos); // 0-0:1.1's device_name never surfaces

    const bool found_domain0 = std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
        return r == "thunderbolt|domain0|host_controller|-|-|-|-|-";
    });
    CHECK(found_domain0);
    const bool found_dock = std::any_of(rows.begin(), rows.end(), [](const std::string& r) {
        return r == "thunderbolt|0-1|device|Apple Inc.|Thunderbolt Dock|"
                    "00340000-0055-0000-0000-000000000000|4|1";
    });
    CHECK(found_dock);
}

TEST_CASE("peripherals linux: an absent bus directory is empty, not a failure",
          "[peripherals][linux][walk]") {
    using namespace yuzu::peripherals::lnx;
    // The fixture tree's own root has no sys/bus/nonexistent_kind/devices --
    // reuse it directly rather than modelling a fourth bus.
    std::optional<std::string_view> token;
    const auto rows = usb_rows_at(fixture_root() / "sys" / "bus" / "does_not_exist", token);
    CHECK(rows.empty());
    CHECK_FALSE(token.has_value());
}

#if !defined(_WIN32)
TEST_CASE("peripherals linux: an unreadable root reports linux:sysfs:eacces",
          "[peripherals][linux][walk]") {
    using namespace yuzu::peripherals::lnx;
    yuzu::test::TempDir dir{"yuzu_test_peripherals_linux_eacces_"};
    std::filesystem::create_directories(dir.path);

    // Skip if the test happens to run as root (uid 0 bypasses the
    // permission bits this test exercises) -- e.g. inside an unprivileged
    // Docker CI runner this never triggers, but a local root shell would.
    if (::geteuid() == 0) {
        SUCCEED("running as root -- permission bits are not enforced, skipping");
        return;
    }

    REQUIRE(::chmod(dir.path.string().c_str(), 0000) == 0);

    std::optional<std::string_view> token;
    const auto rows = usb_rows_at(dir.path, token);
    // Restore permissions before TempDir's destructor tries to remove it.
    ::chmod(dir.path.string().c_str(), 0700);

    CHECK(rows.empty());
    REQUIRE(token.has_value());
    CHECK(*token == "linux:sysfs:eacces");
}
#endif
