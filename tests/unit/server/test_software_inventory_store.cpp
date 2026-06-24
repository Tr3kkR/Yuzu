// SoftwareInventoryStore tests (ADR-0016): the born-on-Postgres typed
// projection for the installed_software daily-sync source — canonical-hash
// cross-pin, hash-skip ingest (full/touched/need_full), atomic replace, fleet
// query, and the shared ingest seam (ingest_inventory_report) end-to-end.

#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h"
#include "inventory_ingestion.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_inventory_store.hpp"

#include "../test_helpers.hpp"

#include <libpq-fe.h>

#include <optional>
#include <string>
#include <vector>

using yuzu::server::InventoryIngestOutcome;
using yuzu::server::SoftwareEntry;
using yuzu::server::SoftwareFleetQuery;
using yuzu::server::SoftwareInventoryStore;
using yuzu::server::pg::PgPool;
namespace agentpb = yuzu::agent::v1;

namespace {
// THE cross-side pin (ADR-0016 §4): the agent computes the SAME hash for the
// SAME input (see tests/unit/test_inventory_sync.cpp — identical constant). If
// the agent's and server's canonicalisation ever drift by one byte, one of the
// two assertions fails and the hash-skip optimisation is broken before it ships.
constexpr const char* kCrossPinHash =
    "d7a11c1cc4987d05049f7d3226b23b9324f5fa703c8474ba0c36b4807ee5f9b8";

// Canonical wire blob for one entry (fields 0x1F, entry terminated 0x1E).
std::string blob1(const std::string& n, const std::string& v, const std::string& p,
                  const std::string& d) {
    return n + '\x1f' + v + '\x1f' + p + '\x1f' + d + '\x1e';
}
} // namespace

TEST_CASE("SoftwareInventoryStore canonical_hash is the cross-pinned value",
          "[software_inventory][hash]") {
    // Deliberately unsorted + a duplicate: normalize() must sort + dedup to the
    // same canonical bytes the constant was computed from.
    std::vector<SoftwareEntry> e = {
        {"Zeta", "9", "", ""},
        {"Acme Reader", "1.2", "Acme", "2026-01-02"},
        {"Acme Reader", "1.2", "Acme", "2026-01-02"},
    };
    CHECK(SoftwareInventoryStore::canonical_hash(e) == kCrossPinHash);
}

TEST_CASE("SoftwareInventoryStore hash-skip ingest round-trip", "[pg][software_inventory]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    std::vector<SoftwareEntry> rows = {{"Chrome", "119", "Google", "2026-01-01"},
                                       {"Firefox", "120", "Mozilla", ""}};
    const std::string h = SoftwareInventoryStore::canonical_hash(rows);

    SECTION("full payload stores, reads back name-sorted, fleet-queryable") {
        CHECK(store.apply_installed_software("agent-a", h, rows, 1000) ==
              InventoryIngestOutcome::kStored);
        auto got = store.get_agent_software("agent-a");
        REQUIRE(got.size() == 2);
        CHECK(got[0].name == "Chrome");
        CHECK(got[1].name == "Firefox");

        SoftwareFleetQuery q;
        q.name = "Chrome";
        auto fl = store.query_software(q);
        REQUIRE(fl.size() == 1);
        CHECK(fl[0].agent_id == "agent-a");
        CHECK(fl[0].entry.version == "119");
    }

    SECTION("hash-only matching the stored hash → touched, no row change") {
        REQUIRE(store.apply_installed_software("agent-b", h, rows, 1000) ==
                InventoryIngestOutcome::kStored);
        CHECK(store.apply_installed_software("agent-b", h, std::nullopt, 2000) ==
              InventoryIngestOutcome::kTouched);
        CHECK(store.get_agent_software("agent-b").size() == 2);
    }

    SECTION("hash-only with no stored record (cold cache) → need_full") {
        CHECK(store.apply_installed_software("agent-cold", h, std::nullopt, 1000) ==
              InventoryIngestOutcome::kNeedFull);
    }

    SECTION("hash-only with a different hash (drift) → need_full") {
        REQUIRE(store.apply_installed_software("agent-c", h, rows, 1000) ==
                InventoryIngestOutcome::kStored);
        CHECK(store.apply_installed_software("agent-c", "deadbeef", std::nullopt, 2000) ==
              InventoryIngestOutcome::kNeedFull);
    }

    SECTION("a changed full payload replaces the agent's rows atomically") {
        REQUIRE(store.apply_installed_software("agent-d", h, rows, 1000) ==
                InventoryIngestOutcome::kStored);
        std::vector<SoftwareEntry> rows2 = {{"Chrome", "120", "Google", "2026-02-01"}};
        const std::string h2 = SoftwareInventoryStore::canonical_hash(rows2);
        REQUIRE(store.apply_installed_software("agent-d", h2, rows2, 3000) ==
                InventoryIngestOutcome::kStored);
        auto got = store.get_agent_software("agent-d");
        REQUIRE(got.size() == 1);
        CHECK(got[0].version == "120");
    }
}

TEST_CASE("ingest_inventory_report drives the seam + fills need_full",
          "[pg][software_inventory][seam]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    const std::string blob = blob1("Chrome", "119", "Google", "2026-01-01");
    const std::string h =
        SoftwareInventoryStore::canonical_hash({{"Chrome", "119", "Google", "2026-01-01"}});

    SECTION("full payload (hash + blob) ingested, ack has no need_full") {
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = h;
        (*rep.mutable_plugin_data())["installed_software"] = blob;
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-x", rep, ack);
        CHECK(ack.need_full_size() == 0);
        CHECK(store.get_agent_software("agent-x").size() == 1);
    }

    SECTION("hash-only on a cold cache → ack.need_full lists the source") {
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = h; // no blob
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-cold2", rep, ack);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == "installed_software");
    }

    SECTION("unknown source key is ignored (slice 1 wires only installed_software)") {
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["something_else"] = h;
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-y", rep, ack);
        CHECK(ack.need_full_size() == 0);
    }
}
