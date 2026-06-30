// DeviceInventoryStore tests (ADR-0016): the born-on-Postgres device-CI
// projection — canonical-hash cross-pin with the agent, blob parse round-trip,
// hash-skip ingest (full/touched/need_full), single-row replace, roster read,
// delete, and the shared ingest seam (ingest_device_ci_report) end-to-end.

#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h"
#include "device_ci_ingestion.hpp"
#include "device_inventory_store.hpp"
#include "pg/pg_pool.hpp"

#include "../test_helpers.hpp"

#include <optional>
#include <string>

using yuzu::server::CiReadOutcome;
using yuzu::server::DeviceCiRecord;
using yuzu::server::DeviceInventoryStore;
using yuzu::server::InventoryIngestOutcome;
using yuzu::server::parse_device_ci_blob;
using yuzu::server::pg::PgPool;
namespace agentpb = yuzu::agent::v1;

namespace {
// THE cross-side pin (ADR-0016 §4): the agent computes the SAME hash for the SAME
// record (tests/unit/test_device_ci_sync.cpp — identical constant). A one-byte
// drift in either canonicalisation fails one assertion.
constexpr const char* kCrossPinHash =
    "467abd73a70803c5c762a26a4c7ffce536dda060d296ad83aed649473388f975";

// The fixed cross-pin field set, built into the canonical wire blob (the agent's
// CiRecord field order, 0x1F-separated, 0x1E-terminated).
std::string sample_blob() {
    const std::string fields[] = {"Dell Inc.",
                                  "Latitude 7420",
                                  "ABC123",
                                  "4C4C4544-0042-1234-5678-AABBCCDDEEFF",
                                  "WS-001",
                                  "corp.example",
                                  "OU=Laptops,DC=corp,DC=example",
                                  "Dell Inc.",
                                  "1.27.0",
                                  "2024-03-15",
                                  "Intel(R) Core(TM) i7-1185G7",
                                  "4",
                                  "8",
                                  "17179869184",
                                  "Samsung SSD 980 512 SSD",
                                  "00:11:22:33:44:55",
                                  "00:11:22:33:44:55,aa:bb:cc:dd:ee:ff",
                                  "2",
                                  "Windows 11 Pro",
                                  "10.0.22631",
                                  "22631",
                                  "x86_64"};
    std::string b;
    bool first = true;
    for (const auto& f : fields) {
        if (!first)
            b += '\x1f';
        b += f;
        first = false;
    }
    b += '\x1e';
    return b;
}
} // namespace

TEST_CASE("DeviceInventoryStore canonical_hash matches the cross-pin", "[device_ci][hash]") {
    DeviceCiRecord r = parse_device_ci_blob(sample_blob());
    CHECK(DeviceInventoryStore::canonical_hash(r) == kCrossPinHash);
}

TEST_CASE("parse_device_ci_blob round-trips fields positionally", "[device_ci][parse]") {
    DeviceCiRecord r = parse_device_ci_blob(sample_blob());
    CHECK(r.manufacturer == "Dell Inc.");
    CHECK(r.serial == "ABC123");
    CHECK(r.cpu_cores == "4");
    CHECK(r.ram_bytes == "17179869184");
    CHECK(r.macs_summary == "00:11:22:33:44:55,aa:bb:cc:dd:ee:ff");
    CHECK(r.arch == "x86_64");

    SECTION("missing trailing fields stay empty (no crash)") {
        DeviceCiRecord p = parse_device_ci_blob("OnlyMfr\x1fOnlyModel\x1e");
        CHECK(p.manufacturer == "OnlyMfr");
        CHECK(p.model == "OnlyModel");
        CHECK(p.serial.empty());
        CHECK(p.arch.empty());
    }
    SECTION("two fields split positionally on the separators") {
        // Split the \x1f escape from the following 'b' (a hex digit) so it is not
        // parsed as one out-of-range \x1fb escape.
        DeviceCiRecord p = parse_device_ci_blob(std::string("a\x1f"
                                                            "b\x1e"));
        CHECK(p.manufacturer == "a");
        CHECK(p.model == "b");
    }
}

TEST_CASE("DeviceInventoryStore hash-skip ingest round-trip", "[pg][device_ci]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    DeviceCiRecord rec = parse_device_ci_blob(sample_blob());
    const std::string h = DeviceInventoryStore::canonical_hash(rec);

    SECTION("full payload stores, reads back with fields") {
        CHECK(store.apply_device_ci("agent-a", h, std::optional<DeviceCiRecord>{rec}, 1000) ==
              InventoryIngestOutcome::kStored);
        DeviceCiRecord got;
        CHECK(store.get_device_ci("agent-a", got) == CiReadOutcome::kFound);
        CHECK(got.agent_id == "agent-a");
        CHECK(got.manufacturer == "Dell Inc.");
        CHECK(got.serial == "ABC123");
        CHECK(got.cpu_cores == "4");
        CHECK(got.ram_bytes == "17179869184");
        CHECK(got.os_name == "Windows 11 Pro");
        CHECK(got.last_seen > 0);
        CHECK(got.first_seen > 0);
    }

    SECTION("hash-only matching → touched; mismatch / cold → need_full") {
        REQUIRE(store.apply_device_ci("agent-b", h, std::optional<DeviceCiRecord>{rec}, 1000) ==
                InventoryIngestOutcome::kStored);
        // Matching hash, no payload → touched.
        CHECK(store.apply_device_ci("agent-b", h, std::nullopt, 2000) ==
              InventoryIngestOutcome::kTouched);
        // Drifted hash → need_full.
        CHECK(store.apply_device_ci("agent-b", "deadbeef", std::nullopt, 3000) ==
              InventoryIngestOutcome::kNeedFull);
        // Cold cache (unknown agent), hash-only → need_full.
        CHECK(store.apply_device_ci("agent-cold", h, std::nullopt, 4000) ==
              InventoryIngestOutcome::kNeedFull);
    }

    SECTION("first_seen preserved across re-store; last_seen advances") {
        REQUIRE(store.apply_device_ci("agent-c", h, std::optional<DeviceCiRecord>{rec}, 1000) ==
                InventoryIngestOutcome::kStored);
        DeviceCiRecord first;
        REQUIRE(store.get_device_ci("agent-c", first) == CiReadOutcome::kFound);
        // A changed record (different hash) re-stores; first_seen must not move.
        DeviceCiRecord rec2 = rec;
        rec2.model = "Latitude 9430";
        const std::string h2 = DeviceInventoryStore::canonical_hash(rec2);
        REQUIRE(store.apply_device_ci("agent-c", h2, std::optional<DeviceCiRecord>{rec2}, 5000) ==
                InventoryIngestOutcome::kStored);
        DeviceCiRecord second;
        REQUIRE(store.get_device_ci("agent-c", second) == CiReadOutcome::kFound);
        CHECK(second.model == "Latitude 9430");
        CHECK(second.first_seen == first.first_seen);
        CHECK(second.last_seen >= first.last_seen);
    }

    SECTION("roster list + delete + absent") {
        REQUIRE(store.apply_device_ci("agent-d", h, std::optional<DeviceCiRecord>{rec}, 1000) ==
                InventoryIngestOutcome::kStored);
        auto roster = store.list_device_ci(100);
        REQUIRE(roster.has_value());
        bool found = false;
        for (const auto& d : *roster)
            if (d.agent_id == "agent-d")
                found = true;
        CHECK(found);

        store.delete_agent("agent-d");
        DeviceCiRecord gone;
        CHECK(store.get_device_ci("agent-d", gone) == CiReadOutcome::kAbsent);
    }

    SECTION("unknown agent reads kAbsent (not kDegraded)") {
        DeviceCiRecord none;
        CHECK(store.get_device_ci("nobody", none) == CiReadOutcome::kAbsent);
    }
}

TEST_CASE("ingest_device_ci_report end-to-end (both wire shapes)", "[pg][device_ci][ingest]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeviceInventoryStore store{pool};
    REQUIRE(store.is_open());

    const std::string blob = sample_blob();
    const std::string h = DeviceInventoryStore::canonical_hash(parse_device_ci_blob(blob));

    SECTION("full report stores; subsequent hash-only matching report does not nack") {
        agentpb::InventoryReport full;
        (*full.mutable_content_hashes())["device_ci"] = h;
        (*full.mutable_plugin_data())["device_ci"] = blob;
        agentpb::InventoryAck ack;
        yuzu::server::ingest_device_ci_report(store, "agent-e", full, ack, nullptr);
        CHECK(ack.need_full_size() == 0);
        DeviceCiRecord got;
        CHECK(store.get_device_ci("agent-e", got) == CiReadOutcome::kFound);
        CHECK(got.serial == "ABC123");

        agentpb::InventoryReport hashonly;
        (*hashonly.mutable_content_hashes())["device_ci"] = h; // no plugin_data
        agentpb::InventoryAck ack2;
        yuzu::server::ingest_device_ci_report(store, "agent-e", hashonly, ack2, nullptr);
        CHECK(ack2.need_full_size() == 0); // matched → touched, no resend
    }

    SECTION("hash-only with no stored row nacks (cold cache)") {
        agentpb::InventoryReport hashonly;
        (*hashonly.mutable_content_hashes())["device_ci"] = h;
        agentpb::InventoryAck ack;
        yuzu::server::ingest_device_ci_report(store, "agent-cold2", hashonly, ack, nullptr);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == "device_ci");
    }

    SECTION("source absent from the report → no-op, no nack") {
        agentpb::InventoryReport other;
        (*other.mutable_content_hashes())["installed_software"] = "x";
        agentpb::InventoryAck ack;
        yuzu::server::ingest_device_ci_report(store, "agent-f", other, ack, nullptr);
        CHECK(ack.need_full_size() == 0);
    }
}
