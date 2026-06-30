// Device-CI daily-sync tests (ADR-0016): the canonical-hash cross-pin with the
// server (tests/unit/server/test_device_inventory_store.cpp — identical constant)
// and the SyncSource idle-when-a-plugin-is-missing contract.

#include <catch2/catch_test_macros.hpp>

#include "sync_source_device_ci.hpp"
#include "sync_source_installed_software.hpp" // yuzu::agent::sha256_hex

#include <chrono>

using yuzu::agent::CiRecord;
using yuzu::agent::device_ci_canonical_blob;
using yuzu::agent::make_device_ci_source;
using yuzu::agent::sha256_hex;

namespace {
// THE cross-side pin (ADR-0016 §4): the server computes the SAME hash for the SAME
// record (tests/unit/server/test_device_inventory_store.cpp — identical constant).
// A one-byte drift in either canonicalisation fails one assertion and the hash-skip
// optimisation is broken before it ships.
constexpr const char* kCrossPinHash =
    "467abd73a70803c5c762a26a4c7ffce536dda060d296ad83aed649473388f975";

// The fixed cross-pin record. All fields are clean ASCII (no separator/control
// bytes), so the agent clamp is a no-op and the bytes equal the server's raw
// wire-blob → parse round-trip.
CiRecord sample() {
    CiRecord r;
    r.manufacturer = "Dell Inc.";
    r.model = "Latitude 7420";
    r.serial = "ABC123";
    r.system_uuid = "4C4C4544-0042-1234-5678-AABBCCDDEEFF";
    r.hostname = "WS-001";
    r.domain = "corp.example";
    r.ou = "OU=Laptops,DC=corp,DC=example";
    r.bios_vendor = "Dell Inc.";
    r.bios_version = "1.27.0";
    r.bios_date = "2024-03-15";
    r.cpu_model = "Intel(R) Core(TM) i7-1185G7";
    r.cpu_cores = "4";
    r.cpu_threads = "8";
    r.ram_bytes = "17179869184";
    r.disks_summary = "Samsung SSD 980 512 SSD";
    r.primary_mac = "00:11:22:33:44:55";
    r.macs_summary = "00:11:22:33:44:55,aa:bb:cc:dd:ee:ff";
    r.nic_count = "2";
    r.os_name = "Windows 11 Pro";
    r.os_version = "10.0.22631";
    r.os_build = "22631";
    r.arch = "x86_64";
    return r;
}
} // namespace

TEST_CASE("device_ci canonical hash matches the cross-pin", "[sync][device_ci][hash]") {
    CHECK(sha256_hex(device_ci_canonical_blob(sample())) == kCrossPinHash);
}

TEST_CASE("device_ci source idles when a required plugin is missing", "[sync][device_ci]") {
    SECTION("all descriptors null → collect returns nullopt (no partial CI record)") {
        auto src = make_device_ci_source(nullptr, nullptr, nullptr, nullptr);
        CHECK(src.name == "device_ci");
        CHECK(src.interval == std::chrono::hours{24});
        CHECK(!src.collect().has_value());
    }
}
