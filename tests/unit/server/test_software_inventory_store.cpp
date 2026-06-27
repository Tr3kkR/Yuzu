// SoftwareInventoryStore tests (ADR-0016): the born-on-Postgres typed
// projection for the installed_software daily-sync source — canonical-hash
// cross-pin, hash-skip ingest (full/touched/need_full), atomic replace, fleet
// query, and the shared ingest seam (ingest_inventory_report) end-to-end.

#include <catch2/catch_test_macros.hpp>

#include "agent.pb.h"
#include "inventory_ingestion.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "software_inventory_store.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::InventoryIngestOutcome;
using yuzu::server::SoftwareEntry;
using yuzu::server::SoftwareFleetQuery;
using yuzu::server::SoftwareInventoryStore;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;
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
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 2);
        CHECK((*got)[0].name == "Chrome");
        CHECK((*got)[1].name == "Firefox");

        SoftwareFleetQuery q;
        q.name = "Chrome";
        auto fl = store.query_software(q);
        REQUIRE(fl.has_value());
        REQUIRE(fl->size() == 1);
        CHECK((*fl)[0].agent_id == "agent-a");
        CHECK((*fl)[0].entry.version == "119");
    }

    SECTION("hash-only matching the stored hash → touched, no row change") {
        REQUIRE(store.apply_installed_software("agent-b", h, rows, 1000) ==
                InventoryIngestOutcome::kStored);
        CHECK(store.apply_installed_software("agent-b", h, std::nullopt, 2000) ==
              InventoryIngestOutcome::kTouched);
        auto b = store.get_agent_software("agent-b");
        REQUIRE(b.has_value());
        CHECK(b->size() == 2);
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
        REQUIRE(got.has_value());
        REQUIRE(got->size() == 1);
        CHECK((*got)[0].version == "120");
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
        auto x = store.get_agent_software("agent-x");
        REQUIRE(x.has_value());
        CHECK(x->size() == 1);
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

    SECTION("an oversized blob is dropped, nacked, and stores no rows (UP-2/UP-4)") {
        // > 4 MiB per-source cap: the seam must NOT store it (false success) and
        // must nack so the agent resends rather than silently advancing.
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = h;
        (*rep.mutable_plugin_data())["installed_software"] =
            std::string(5u * 1024 * 1024, 'x'); // no separators → still over the cap
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-oversized", rep, ack);
        REQUIRE(ack.need_full_size() == 1);
        CHECK(ack.need_full(0) == "installed_software");
        // Store open + query OK + zero rows = an empty VALUE (a genuine "nothing"),
        // NOT nullopt (which is reserved for a degrade — ADR-0016 §7).
        auto os = store.get_agent_software("agent-oversized");
        REQUIRE(os.has_value());
        CHECK(os->empty());
    }
}

TEST_CASE("ingest boundary-truncates an over-long multibyte field so PG accepts it (UP-10)",
          "[pg][software_inventory][seam]") {
    // Regression for the UTF-8 byte-cut: a raw field whose multibyte codepoint
    // straddles the 1024-byte cap must be truncated on the codepoint boundary, NOT
    // mid-sequence — otherwise the INSERT into the UTF8 TEXT column is rejected by
    // PostgreSQL (22021) → kError → need_full, never storing. The row must STORE.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    // name = 1023 'a' + 'é' (0xC3 0xA9) = 1025 bytes; record = name|1|| (0x1F fields,
    // 0x1E terminator; octal \037=0x1F \036=0x1E to avoid greedy \x hex escapes).
    std::string longname = std::string(1023, 'a') + "\xc3\xa9";
    std::string blob = longname + "\0371\037\037\036";
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = "x"; // recomputed on a full payload
    (*rep.mutable_plugin_data())["installed_software"] = blob;
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-utf8", rep, ack);
    CHECK(ack.need_full_size() == 0); // STORED, not kError-nacked (PG accepted valid UTF-8)
    auto rows = store.get_agent_software("agent-utf8");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].name == std::string(1023, 'a')); // boundary-truncated, valid UTF-8
}

TEST_CASE("ingest scrubs invalid UTF-8 to U+FFFD so PG accepts it + hash matches the agent (UP-IN1)",
          "[pg][software_inventory][seam]") {
    // A non-conforming agent (or a future SyncSource that does not pre-scrub) sends a
    // RAW cp1252 byte 0xE9 ("Café" = 43 61 66 E9) in the name. PG's UTF8 TEXT column
    // would reject it (22021) → kError → permanent resend (UP-IN1). The seam must
    // replace it with U+FFFD (EF BF BD) IDENTICALLY to the agent's clamp_field, so the
    // row STORES and the server-recomputed hash equals what the real agent (which
    // scrubs before hashing) would have sent.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    // The hash the agent would compute AFTER its own identical scrub of 0xE9.
    const std::string agent_hash = SoftwareInventoryStore::canonical_hash(
        {{std::string("Caf\xef\xbf\xbd"), "1", "Acme", "2020"}});

    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = agent_hash;
    (*rep.mutable_plugin_data())["installed_software"] = blob1("Caf\xe9", "1", "Acme", "2020");
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-utf8-scrub", rep, ack);
    CHECK(ack.need_full_size() == 0); // STORED, not 22021-rejected → kError-nacked

    auto rows = store.get_agent_software("agent-utf8-scrub");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].name == std::string("Caf\xef\xbf\xbd")); // raw 0xE9 scrubbed to U+FFFD
    CHECK((*rows)[0].name.find('\xe9') == std::string::npos);

    // Cross-pin: a hash-only follow-up carrying the agent's hash → touched (no
    // need_full) proves the server-recomputed stored hash equals the agent's, i.e.
    // the two scrubs are byte-coordinated.
    agentpb::InventoryReport rep2;
    (*rep2.mutable_content_hashes())["installed_software"] = agent_hash; // no blob
    agentpb::InventoryAck ack2;
    yuzu::server::ingest_inventory_report(store, "agent-utf8-scrub", rep2, ack2);
    CHECK(ack2.need_full_size() == 0);
}

TEST_CASE("ingest scrub: PG-strict edge-branch parity vector (UP-IN1 drift guard)",
          "[pg][software_inventory][seam]") {
    // These two literals are duplicated VERBATIM from the agent suite
    // (test_inventory_sync.cpp kScrubVectorRaw/kScrubVectorExpected). The agent's
    // clamp_field and the server's parse_software_blob MUST scrub identically or the
    // canonical hashes diverge → permanent always-full. Editing one scrub copy without
    // the other fails one of these two tests (gov Gate-8 drift guard).
    const std::string raw = std::string("X") + "\xc0\x80" + "\xed\xa0\x80" + "\xf4\x90\x80\x80" +
                            "\xc3\xa9" + "\xf0\x9f\x98\x80" + "\xf5";
    const std::string expected =
        std::string("X") + "\xef\xbf\xbd\xef\xbf\xbd" + "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" +
        "\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd" + "\xc3\xa9" + "\xf0\x9f\x98\x80" +
        "\xef\xbf\xbd";

    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    // The hash the agent would compute after its identical scrub.
    const std::string agent_hash =
        SoftwareInventoryStore::canonical_hash({{expected, "1", "p", "d"}});
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = agent_hash;
    (*rep.mutable_plugin_data())["installed_software"] = blob1(raw, "1", "p", "d");
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-scrub-vec", rep, ack);
    CHECK(ack.need_full_size() == 0); // PG accepted the scrubbed valid UTF-8

    auto rows = store.get_agent_software("agent-scrub-vec");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].name == expected); // server scrub == agent scrub, byte-for-byte
}

TEST_CASE("ingest_inventory_report nacks need_full when the store ERRORS (UP-2 kError path)",
          "[pg][software_inventory][seam]") {
    // The UP-2 hardening: when apply_installed_software returns kError (a transient
    // store failure, NOT a cold cache), the seam must nack need_full so the agent
    // resends rather than silently advancing past un-stored data. Every other seam
    // test hits kStored/kTouched/kNeedFull/dropped; this is the only one that drives
    // the kError branch (QE Gate-8 coverage gap). Induced by dropping the store's
    // schema out from under an open store so the full-payload transaction's first
    // statement fails (kError, returned not thrown — verified in the store).
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult drop =
            pg::exec_params(lease.get(), "DROP SCHEMA software_inventory_store CASCADE",
                            std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }

    const std::string blob = blob1("Chrome", "119", "Google", "2026-01-01");
    const std::string h =
        SoftwareInventoryStore::canonical_hash({{"Chrome", "119", "Google", "2026-01-01"}});
    agentpb::InventoryReport rep;
    (*rep.mutable_content_hashes())["installed_software"] = h;
    (*rep.mutable_plugin_data())["installed_software"] = blob; // FULL payload → exercises apply
    agentpb::InventoryAck ack;
    yuzu::server::ingest_inventory_report(store, "agent-err", rep, ack);
    REQUIRE(ack.need_full_size() == 1);
    CHECK(ack.need_full(0) == "installed_software");
}

TEST_CASE("reads are AUTHORITATIVE: a degrade returns nullopt, distinct from a true empty "
          "(ADR-0016 §7 / fjarvis HIGH)",
          "[pg][software_inventory]") {
    // The frozen ADR-0016 §7 contract: a read surfaces a store/pool/query failure as
    // nullopt, NEVER a silent empty — else a fleet vuln query reads a transient PG
    // failure as "installed nowhere" (the fail-open A4 violation fjarvis blocked on).
    // A genuine zero-row read stays an empty VALUE.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    SECTION("a genuine zero-row read is an empty VALUE, not nullopt") {
        SoftwareFleetQuery q;
        q.name = "No Such Package";
        auto fl = store.query_software(q);
        REQUIRE(fl.has_value()); // not a degrade
        CHECK(fl->empty());      // genuinely nothing installed
        auto one = store.get_agent_software("no-such-agent");
        REQUIRE(one.has_value());
        CHECK(one->empty());
    }

    SECTION("a backend failure (schema dropped) returns nullopt, not a silent empty") {
        {
            auto lease = pool.try_acquire_for(std::chrono::seconds{5});
            REQUIRE(lease);
            pg::PgResult drop =
                pg::exec_params(lease.get(), "DROP SCHEMA software_inventory_store CASCADE",
                                std::vector<std::string>{});
            REQUIRE(drop.status() == PGRES_COMMAND_OK);
        }
        SoftwareFleetQuery q;
        q.name = "Chrome";
        CHECK_FALSE(store.query_software(q).has_value());          // degraded → nullopt
        CHECK_FALSE(store.get_agent_software("agent-a").has_value()); // not a silent empty
    }
}

TEST_CASE("ingest rejects a report carrying too many sources (map-cardinality cap)",
          "[pg][software_inventory][seam]") {
    // Defense-in-depth (fjarvis LOW): the framework wires a small fixed number of
    // sources; an implausibly large content_hashes/plugin_data map is malformed or
    // abusive and the whole report is rejected (no per-source processing, no rows).
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    SECTION("content_hashes map over cap → rejected") {
        agentpb::InventoryReport rep;
        for (int i = 0; i < 100; ++i) // > kMaxSources (64)
            (*rep.mutable_content_hashes())["src-" + std::to_string(i)] = "h";
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-flood", rep, ack);
        CHECK(ack.need_full_size() == 0); // whole report dropped, no per-source nack
        auto rows = store.get_agent_software("agent-flood");
        REQUIRE(rows.has_value());
        CHECK(rows->empty()); // nothing ingested
    }

    SECTION("plugin_data map over cap → rejected (the OR's right arm)") {
        agentpb::InventoryReport rep;
        for (int i = 0; i < 100; ++i)
            (*rep.mutable_plugin_data())["src-" + std::to_string(i)] = "blob";
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-flood2", rep, ack);
        CHECK(ack.need_full_size() == 0);
        auto rows = store.get_agent_software("agent-flood2");
        REQUIRE(rows.has_value());
        CHECK(rows->empty());
    }
}

TEST_CASE("batched insert round-trips a large set, array metacharacters, and empty (#1664)",
          "[pg][software_inventory]") {
    // The per-row INSERT loop is now one `unnest($N::text[])` statement. These
    // exercise it against a real backend: bulk correctness, the text[] literal
    // escaping (to_text_array — unit-tested in test_pg_array.cpp, end-to-end
    // here), and the empty-entries skip.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    SECTION("the documented max (kMaxEntries) inserts via one unnest() and reads back complete") {
        // 20 000 rows — the kMaxEntries cap, i.e. the largest payload the ingest
        // accepts. A multi-row VALUES would exceed libpq's 65535-param ceiling
        // here (5 params/row); the unnest path binds a constant 5 params.
        constexpr int kRows = 20000;
        std::vector<SoftwareEntry> rows;
        rows.reserve(kRows);
        for (int i = 0; i < kRows; ++i)
            rows.push_back({"pkg-" + std::to_string(i), std::to_string(i), "Pub", "2026-01-01"});
        const std::string h = SoftwareInventoryStore::canonical_hash(rows);
        REQUIRE(store.apply_installed_software("agent-big", h, rows, 1000) ==
                InventoryIngestOutcome::kStored);
        auto got = store.get_agent_software("agent-big");
        REQUIRE(got.has_value());
        CHECK(got->size() == kRows);
    }

    SECTION("array metacharacters in name/publisher survive the text[] literal round-trip") {
        // Comma, double-quote, backslash, and braces are exactly the bytes
        // to_text_array escapes; a regression would corrupt or 22P02-reject the
        // whole batch. Verified via the exact-name fleet query (collation-stable).
        const std::string meta = "a,b\"c\\d{e}";
        std::vector<SoftwareEntry> rows = {{meta, "1", "Vendor, Inc.", ""}, {"Plain", "2", "", ""}};
        const std::string h = SoftwareInventoryStore::canonical_hash(rows);
        REQUIRE(store.apply_installed_software("agent-meta", h, rows, 1000) ==
                InventoryIngestOutcome::kStored);
        SoftwareFleetQuery q;
        q.name = meta;
        auto fl = store.query_software(q);
        REQUIRE(fl.has_value());
        REQUIRE(fl->size() == 1);
        CHECK((*fl)[0].agent_id == "agent-meta");
        CHECK((*fl)[0].entry.name == meta); // exact round-trip, not just queryable
        CHECK((*fl)[0].entry.publisher == "Vendor, Inc.");
    }

    SECTION("a full payload with zero entries stores nothing and is a clean empty") {
        std::vector<SoftwareEntry> none;
        const std::string h = SoftwareInventoryStore::canonical_hash(none);
        REQUIRE(store.apply_installed_software("agent-empty", h, none, 1000) ==
                InventoryIngestOutcome::kStored);
        auto got = store.get_agent_software("agent-empty");
        REQUIRE(got.has_value());
        CHECK(got->empty());
        // Hash-only follow-up with the same (empty) hash → touched proves the
        // parent row + the empty content_hash persisted.
        CHECK(store.apply_installed_software("agent-empty", h, std::nullopt, 2000) ==
              InventoryIngestOutcome::kTouched);
    }
}

TEST_CASE("read-degrade bumps yuzu_inventory_read_degrade_total by reason (#1675)",
          "[pg][software_inventory]") {
    // The authoritative-read degrade is dashboard-invisible (/readyz stays green
    // under pure saturation), so the counter is the only signal. Dropping the
    // schema under the open store forces a query_error on both reads.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult drop =
            pg::exec_params(lease.get(), "DROP SCHEMA software_inventory_store CASCADE",
                            std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }
    SoftwareFleetQuery q;
    q.name = "Chrome";
    CHECK_FALSE(store.query_software(q).has_value()); // degraded → nullopt
    CHECK_FALSE(store.get_agent_software("agent-a").has_value());
    CHECK(metrics.counter("yuzu_inventory_read_degrade_total", {{"reason", "query_error"}})
              .value() == 2.0);
}

TEST_CASE("count_stale_agents keys on server receipt time, immune to agent collected_at skew "
          "(#1685)",
          "[pg][software_inventory]") {
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
    std::vector<SoftwareEntry> rows = {{"Chrome", "1", "", ""}};
    const std::string h = SoftwareInventoryStore::canonical_hash(rows);

    // A future-skewed (or hostile) agent supplies collected_at far ahead of now.
    // Pre-fix this stamped last_seen into the future, so the agent could go dark
    // and never satisfy `last_seen < cutoff` — hidden from the freshness gauge
    // forever (#1685). Post-fix last_seen is the SERVER receipt time (~now), so the
    // skew is ignored. collected_at is otherwise unobservable from the store, so
    // the gauge is the only lever to assert through.
    const std::int64_t far_future = now + 100'000'000; // ~3 years ahead
    REQUIRE(store.apply_installed_software("agent-skew", h, rows, far_future) ==
            InventoryIngestOutcome::kStored);
    REQUIRE(store.apply_installed_software("agent-honest", h, rows, now) ==
            InventoryIngestOutcome::kStored);

    // Against a past cutoff neither is stale (both last_seen ≈ now).
    auto fresh = store.count_stale_agents(now - 1'000);
    REQUIRE(fresh.has_value());
    CHECK(*fresh == 0);

    // Against a future cutoff BOTH count — proving agent-skew's last_seen sits at
    // ~now, NOT the far-future collected_at it supplied. Pre-fix this would be 1
    // (the skewed agent hidden above the cutoff); the fix makes it 2.
    auto all_stale = store.count_stale_agents(now + 50'000'000);
    REQUIRE(all_stale.has_value());
    CHECK(*all_stale == 2);

    // Partial-count coverage (preserved from the prior collected_at-based test):
    // backdate one agent's SERVER last_seen 10 days — there is no clock seam, so go
    // direct — and confirm only it falls outside the real 2-day window.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto upd = pg::exec_params(
            lease.get(),
            "UPDATE software_inventory_store.inventory_state SET last_seen = $2::bigint "
            "WHERE agent_id = $1",
            std::vector<std::string>{"agent-honest", std::to_string(now - 10 * 86'400)});
        REQUIRE(upd.status() == PGRES_COMMAND_OK);
    }
    auto window = store.count_stale_agents(now - 2 * 86'400);
    REQUIRE(window.has_value());
    CHECK(*window == 1); // only the backdated agent-honest; agent-skew is fresh (~now)
}

TEST_CASE("ingest_inventory_report records the ingest-duration histogram by phase (#1664)",
          "[pg][software_inventory][seam]") {
    // Drives the seam with a LIVE registry (the other seam tests pass nullptr) and
    // asserts the histogram fires once per phase: a full payload → phase=full, a
    // hash-only follow-up → phase=hash_only.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;

    const std::string blob = blob1("Chrome", "119", "Google", "2026-01-01");
    const std::string h =
        SoftwareInventoryStore::canonical_hash({{"Chrome", "119", "Google", "2026-01-01"}});

    {
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = h;
        (*rep.mutable_plugin_data())["installed_software"] = blob; // full payload
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-hist", rep, ack, &metrics);
    }
    {
        agentpb::InventoryReport rep;
        (*rep.mutable_content_hashes())["installed_software"] = h; // hash-only (no blob)
        agentpb::InventoryAck ack;
        yuzu::server::ingest_inventory_report(store, "agent-hist", rep, ack, &metrics);
    }

    auto full = metrics
                    .histogram("yuzu_inventory_ingest_duration_seconds",
                               {{"source", "installed_software"}, {"phase", "full"}})
                    .snapshot();
    auto hash_only = metrics
                         .histogram("yuzu_inventory_ingest_duration_seconds",
                                    {{"source", "installed_software"}, {"phase", "hash_only"}})
                         .snapshot();
    CHECK(full.count == 1);
    CHECK(hash_only.count == 1);
}

TEST_CASE("read-degrade store_not_open reason fires when the store failed to open (#1675)",
          "[pg][software_inventory]") {
    // The store_not_open degrade reason (the other testable degrade besides
    // query_error). Force open_=false by wiping the version record after a normal
    // open so a second construction re-runs the v1 DDL against the already-existing
    // tables → migration fails → !is_open(). Then both authoritative reads must
    // bump the store_not_open counter.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    { // first construction creates the schema, tables, and the schema_meta row
        SoftwareInventoryStore s1{pool};
        REQUIRE(s1.is_open());
    }
    { // wipe the applied-version record so the runner re-applies v1 over live tables
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult del = pg::exec_params(
            lease.get(),
            "DELETE FROM public.schema_meta WHERE store = 'software_inventory_store'",
            std::vector<std::string>{});
        REQUIRE(del.status() == PGRES_COMMAND_OK);
    }
    SoftwareInventoryStore store{pool};
    REQUIRE_FALSE(store.is_open()); // migration re-run failed → store_not_open
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);

    SoftwareFleetQuery q;
    q.name = "Chrome";
    CHECK_FALSE(store.query_software(q).has_value());
    CHECK_FALSE(store.get_agent_software("agent-a").has_value());
    CHECK(metrics.counter("yuzu_inventory_read_degrade_total", {{"reason", "store_not_open"}})
              .value() == 2.0);
}

TEST_CASE("migration v3 backfill clamps pre-fix future last_seen/first_seen at re-open "
          "(#1685 / governance UP-10)",
          "[pg][software_inventory]") {
    // The forward write fix can't re-stamp a dark agent, so v3 must clamp rows that
    // were ALREADY persisted with a future-skewed timestamp. Reproduce a pre-fix
    // row, roll the recorded schema version back to 2 so a fresh construction
    // re-runs ONLY v3 (a DML, re-run-safe), and prove the clamp moved it back into
    // the freshness window.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
    const std::int64_t far_future = now + 100'000'000;
    { // first construction creates schema + tables + schema_meta @ v3 (v3 no-ops on empty)
        SoftwareInventoryStore s1{pool};
        REQUIRE(s1.is_open());
    }
    { // seed a pre-fix future-skewed row, then roll the recorded version back to 2
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult ins = pg::exec_params(
            lease.get(),
            "INSERT INTO software_inventory_store.inventory_state "
            "(agent_id, source, content_hash, first_seen, last_seen) "
            "VALUES ('agent-future', 'installed_software', 'deadbeef', $1::bigint, $1::bigint)",
            std::vector<std::string>{std::to_string(far_future)});
        REQUIRE(ins.status() == PGRES_COMMAND_OK);
        pg::PgResult back = pg::exec_params(
            lease.get(),
            "UPDATE public.schema_meta SET version = 2 WHERE store = 'software_inventory_store'",
            std::vector<std::string>{});
        REQUIRE(back.status() == PGRES_COMMAND_OK);
    }
    SoftwareInventoryStore store{pool}; // re-runs v3 → clamps the future row
    REQUIRE(store.is_open());

    // Discriminator: against a cutoff between now and far_future, the CLAMPED row
    // (last_seen ≈ now) counts stale; an un-clamped row (last_seen = far_future)
    // would sit above the cutoff and count 0.
    auto stale = store.count_stale_agents(now + 50'000'000);
    REQUIRE(stale.has_value());
    CHECK(*stale == 1);

    // first_seen is clamped too (UP-10) — assert it is no longer in the future.
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult sel = pg::exec_params(
            lease.get(),
            "SELECT first_seen FROM software_inventory_store.inventory_state "
            "WHERE agent_id = 'agent-future'",
            std::vector<std::string>{});
        REQUIRE(sel.status() == PGRES_TUPLES_OK);
        REQUIRE(PQntuples(sel.get()) == 1);
        const std::int64_t first_seen = std::stoll(PQgetvalue(sel.get(), 0, 0));
        CHECK(first_seen <= now + 5); // clamped to ~now (small margin for a clock tick)
    }
}

TEST_CASE("read-degrade sampler is data-race-free under concurrent degraded reads "
          "(#1686 DegradeSampler — TSan guard)",
          "[pg][software_inventory]") {
    // The episode WARN sampler's DegradeSampler uses two std::atomics. A regression
    // dropping the atomics would be a data race invisible to a single-threaded test
    // but flagged by ThreadSanitizer here. Drop the schema so every read degrades via
    // the query_error path, then hammer it from many threads. NB: no Catch2 assertion
    // runs INSIDE the threads (Catch2's macros aren't thread-safe — that would flag
    // Catch2, not our code); all assertions run after join on the exact counter.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    yuzu::MetricsRegistry metrics;
    store.set_metrics(&metrics);
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult drop = pg::exec_params(
            lease.get(), "DROP SCHEMA software_inventory_store CASCADE", std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }
    constexpr int kThreads = 8;
    constexpr int kPerThread = 50;
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < kPerThread; ++i) {
                SoftwareFleetQuery q;
                q.name = "Chrome";
                (void)store.query_software(q);       // → query_error degrade
                (void)store.get_agent_software("agent-x"); // → query_error degrade
            }
        });
    }
    for (auto& th : threads)
        th.join();
    // The counter is exact regardless of WARN sampling: every degraded read bumped it
    // exactly once, two reads per iteration.
    const double total =
        metrics.counter("yuzu_inventory_read_degrade_total", {{"reason", "query_error"}}).value();
    CHECK(total == static_cast<double>(kThreads * kPerThread * 2));
}

TEST_CASE("count_stale_agents returns nullopt on a backend degrade (freeze-counter trigger)",
          "[pg][software_inventory]") {
    // The server gauge sweep bumps yuzu_inventory_stale_count_unavailable_total in
    // the else-branch of `if (auto stale = count_stale_agents(...))`. Prove the
    // store method returns nullopt (not a false 0) when the backend is unavailable,
    // so the gauge holds its prior value and the freeze counter fires.
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());
    {
        auto lease = pool.try_acquire_for(std::chrono::seconds{5});
        REQUIRE(lease);
        pg::PgResult drop =
            pg::exec_params(lease.get(), "DROP SCHEMA software_inventory_store CASCADE",
                            std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }
    CHECK_FALSE(store.count_stale_agents(1'000'000).has_value()); // degrade → nullopt, never 0
}

TEST_CASE("delete_agent removes both the child rows and the parent state row",
          "[pg][software_inventory]") {
    // delete_agent deletes from installed_software AND inventory_state in one txn.
    // Verify both halves: the child rows are gone (get returns an empty VALUE, not
    // nullopt) AND the parent state row is gone (a hash-only follow-up sees a cold
    // cache → kNeedFull, not kTouched on a stale parent).
    YUZU_REQUIRE_PG_DB(db);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    SoftwareInventoryStore store{pool};
    REQUIRE(store.is_open());

    std::vector<SoftwareEntry> rows = {{"Chrome", "119", "Google", "2026-01-01"},
                                       {"Firefox", "120", "Mozilla", ""}};
    const std::string h = SoftwareInventoryStore::canonical_hash(rows);
    REQUIRE(store.apply_installed_software("agent-del", h, rows, 1000) ==
            InventoryIngestOutcome::kStored);
    // A bystander agent that must SURVIVE the delete — without this, a DELETE
    // missing its `WHERE agent_id=$1` (a whole-table wipe) would pass every other
    // assertion here. This is the minimal proof the delete is agent-scoped.
    std::vector<SoftwareEntry> by_rows = {{"Edge", "120", "Microsoft", ""}};
    const std::string by_h = SoftwareInventoryStore::canonical_hash(by_rows);
    REQUIRE(store.apply_installed_software("agent-bystander", by_h, by_rows, 1000) ==
            InventoryIngestOutcome::kStored);
    {
        auto pre = store.get_agent_software("agent-del");
        REQUIRE(pre.has_value());
        REQUIRE(pre->size() == 2);
    }

    store.delete_agent("agent-del");

    auto post = store.get_agent_software("agent-del");
    REQUIRE(post.has_value()); // store still open + query OK → empty VALUE, not a degrade
    CHECK(post->empty());      // child rows gone
    // Parent state row gone: a hash-only report now hits a cold cache.
    CHECK(store.apply_installed_software("agent-del", h, std::nullopt, 2000) ==
          InventoryIngestOutcome::kNeedFull);

    // Cross-agent isolation: the bystander's child rows AND parent state row are
    // untouched (its hash-only follow-up still matches → kTouched, not kNeedFull).
    auto bystander = store.get_agent_software("agent-bystander");
    REQUIRE(bystander.has_value());
    REQUIRE(bystander->size() == 1);
    CHECK((*bystander)[0].name == "Edge");
    CHECK(store.apply_installed_software("agent-bystander", by_h, std::nullopt, 2000) ==
          InventoryIngestOutcome::kTouched);

    // A delete of an unknown agent is a no-op (best-effort), not a throw or a degrade.
    store.delete_agent("agent-never-existed");
    auto other = store.get_agent_software("agent-never-existed");
    REQUIRE(other.has_value());
    CHECK(other->empty());
}
