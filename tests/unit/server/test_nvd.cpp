/**
 * test_nvd.cpp — Unit tests for NVD database, version comparison, and JSON parsing
 *
 * Covers: compare_versions() (shared numeric comparator, unchanged),
 *         nvd_version_compare()/nvd_version_in_range() (NVD-grade),
 *         NvdDatabase CRUD + cpeMatch-range match_inventory(),
 *         NvdClient::parse_response().
 */

#include "nvd_client.hpp"
#include "nvd_db.hpp"
#include "nvd_version.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;

namespace {
// A CVE with a single product/version-end-excluding cpeMatch (the common case
// and the shape the builtin rules use).
CveRecord make_cve(std::string id, std::string product, std::string end_excluding,
                   std::string severity = "HIGH") {
    CveRecord rec;
    rec.cve_id = std::move(id);
    rec.severity = std::move(severity);
    rec.description = "Test vulnerability";
    rec.source = "nvd";
    CpeMatch cm;
    cm.cpe_product = std::move(product);
    cm.version_end_excluding = std::move(end_excluding);
    rec.matches.push_back(std::move(cm));
    return rec;
}
} // namespace

// ── Shared numeric comparator (compare_versions) — unchanged, must stay green ──

TEST_CASE("compare_versions: equal versions", "[nvd][version]") {
    REQUIRE(compare_versions("1.0.0", "1.0.0") == 0);
}

TEST_CASE("compare_versions: numeric not lexicographic", "[nvd][version]") {
    REQUIRE(compare_versions("1.10.0", "1.9.0") > 0);
    REQUIRE(compare_versions("1.9.0", "1.10.0") < 0);
}

TEST_CASE("compare_versions: missing segments", "[nvd][version]") {
    REQUIRE(compare_versions("1.0", "1.0.0") == 0);
    REQUIRE(compare_versions("1", "1.0.0") == 0);
}

// ── NVD-grade comparator (nvd_version_compare) ───────────────────────────────

TEST_CASE("nvd_version_compare: basic ordering", "[nvd][version]") {
    REQUIRE(nvd_version_compare("1.0.0", "1.0.0") == 0);
    REQUIRE(nvd_version_compare("1.2.3", "1.2.4") < 0);
    REQUIRE(nvd_version_compare("2.0.0", "1.0.0") > 0);
    REQUIRE(nvd_version_compare("1.10.0", "1.9.0") > 0);
    REQUIRE(nvd_version_compare("124.0.6367.202", "124.0.6367.201") > 0);
}

TEST_CASE("nvd_version_compare: padding is equal", "[nvd][version]") {
    REQUIRE(nvd_version_compare("1.0", "1.0.0") == 0);
    REQUIRE(nvd_version_compare("1", "1.0.0") == 0);
    REQUIRE(nvd_version_compare("1.0.1", "1.0") > 0);
}

TEST_CASE("nvd_version_compare: pre-release ordering", "[nvd][version]") {
    REQUIRE(nvd_version_compare("1.0.0-alpha", "1.0.0-beta") < 0);
    REQUIRE(nvd_version_compare("1.0.0-beta", "1.0.0-rc1") < 0);
    REQUIRE(nvd_version_compare("1.0.0-rc1", "1.0.0") < 0);
    REQUIRE(nvd_version_compare("1.0.0-rc2", "1.0.0-rc1") > 0);
    REQUIRE(nvd_version_compare("1.0.0", "1.0.0-rc1") > 0);
}

TEST_CASE("nvd_version_compare: numeric outranks alpha at same position", "[nvd][version]") {
    // Vendor patch suffixes: a trailing non-prerelease alpha is HIGHER.
    REQUIRE(nvd_version_compare("9.8p1", "9.8") > 0);   // openssh
    REQUIRE(nvd_version_compare("1.0.2k", "1.0.2") > 0); // openssl letter releases
    REQUIRE(nvd_version_compare("1.9.5p2", "1.9.5p3") < 0);
}

TEST_CASE("nvd_version_compare: epoch stripped and ignored", "[nvd][version]") {
    REQUIRE(nvd_version_compare("1:1.0", "1.0") == 0);
    REQUIRE(nvd_version_compare("0:2.0", "2.0") == 0);
}

TEST_CASE("nvd_version_compare: empty strings", "[nvd][version]") {
    REQUIRE(nvd_version_compare("", "") == 0);
    REQUIRE(nvd_version_compare("1.0", "") > 0);
    REQUIRE(nvd_version_compare("", "1.0") < 0);
}

// ── Range predicate (nvd_version_in_range) ───────────────────────────────────
// VersionRange fields: {exact, start_including, start_excluding,
//                       end_including, end_excluding}

TEST_CASE("nvd_version_in_range: end excluding", "[nvd][range]") {
    VersionRange r{"", "", "", "", "3.0.7"};
    REQUIRE(nvd_version_in_range("3.0.6", r));
    REQUIRE_FALSE(nvd_version_in_range("3.0.7", r));
    REQUIRE_FALSE(nvd_version_in_range("3.1.0", r));
}

TEST_CASE("nvd_version_in_range: end including", "[nvd][range]") {
    VersionRange r{"", "", "", "3.0.7", ""};
    REQUIRE(nvd_version_in_range("3.0.7", r));
    REQUIRE_FALSE(nvd_version_in_range("3.0.8", r));
}

TEST_CASE("nvd_version_in_range: start+end band", "[nvd][range]") {
    VersionRange r{"", "2.0", "", "", "3.0"}; // [2.0, 3.0)
    REQUIRE(nvd_version_in_range("2.0", r));
    REQUIRE(nvd_version_in_range("2.5", r));
    REQUIRE_FALSE(nvd_version_in_range("1.9", r));
    REQUIRE_FALSE(nvd_version_in_range("3.0", r));
}

TEST_CASE("nvd_version_in_range: start excluding", "[nvd][range]") {
    VersionRange r{"", "", "2.0", "", ""}; // (2.0, )
    REQUIRE_FALSE(nvd_version_in_range("2.0", r));
    REQUIRE(nvd_version_in_range("2.1", r));
}

TEST_CASE("nvd_version_in_range: exact pin", "[nvd][range]") {
    VersionRange r{"1.2.3", "", "", "", ""};
    REQUIRE(nvd_version_in_range("1.2.3", r));
    REQUIRE_FALSE(nvd_version_in_range("1.2.4", r));
}

TEST_CASE("nvd_version_in_range: wildcard / no constraint means all versions", "[nvd][range]") {
    REQUIRE(nvd_version_in_range("9.9.9", VersionRange{"*", "", "", "", ""}));
    REQUIRE(nvd_version_in_range("9.9.9", VersionRange{"-", "", "", "", ""}));
    REQUIRE(nvd_version_in_range("9.9.9", VersionRange{"", "", "", "", ""}));
}

// ── NvdDatabase ──────────────────────────────────────────────────────────────

TEST_CASE("NvdDatabase: open in-memory", "[nvd][db]") {
    NvdDatabase db(":memory:");
    REQUIRE(db.is_open());
}

TEST_CASE("NvdDatabase: upsert and count", "[nvd][db]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));
    REQUIRE(db.total_cve_count() == 1);
}

TEST_CASE("NvdDatabase: upsert batch", "[nvd][db]") {
    NvdDatabase db(":memory:");
    std::vector<CveRecord> records;
    for (int i = 0; i < 5; ++i)
        records.push_back(make_cve("CVE-2024-000" + std::to_string(i), "test", "1.0"));
    db.upsert_cves(records);
    REQUIRE(db.total_cve_count() == 5);
}

TEST_CASE("NvdDatabase: upsert same ID replaces header, count stays 1", "[nvd][db]") {
    NvdDatabase db(":memory:");
    auto rec = make_cve("CVE-2024-0001", "test", "1.0", "LOW");
    db.upsert_cve(rec);
    rec.severity = "CRITICAL";
    db.upsert_cve(rec);
    REQUIRE(db.total_cve_count() == 1);
}

TEST_CASE("NvdDatabase: header-only CVE counted, never matches", "[nvd][db]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-5000";
    rec.severity = "HIGH";
    rec.description = "no cpe";
    rec.source = "nvd";
    db.upsert_cve(rec); // no matches
    REQUIRE(db.total_cve_count() == 1);
    REQUIRE(db.match_inventory({{"anything", "1.0"}}).empty());
}

TEST_CASE("NvdDatabase: metadata round-trip", "[nvd][db]") {
    NvdDatabase db(":memory:");
    db.set_meta("last_sync", "2024-01-01T00:00:00Z");
    REQUIRE(db.get_meta("last_sync") == "2024-01-01T00:00:00Z");
    REQUIRE(db.get_meta("nonexistent").empty());
}

TEST_CASE("NvdDatabase: seed_builtin_rules is idempotent", "[nvd][db]") {
    NvdDatabase db(":memory:");
    db.seed_builtin_rules();
    auto count1 = db.total_cve_count();
    db.seed_builtin_rules();
    auto count2 = db.total_cve_count();
    REQUIRE(count1 == count2);
    REQUIRE(count1 > 0);
}

// ── v1 -> v2 schema migration (real upgrade path) ────────────────────────────

TEST_CASE("NvdDatabase: v1 database with data upgrades to v2", "[nvd][db][migration]") {
    yuzu::test::TempDbFile tmp{std::string_view{"nvd-migration-"}};
    const std::string path = tmp.path.string();

    // 1. Hand-build a v1-schema database on disk: the OLD flat cve table with a
    //    real row, a sync cursor, and schema_meta pinned at version 1 — exactly
    //    what a persisted volume from before this change looks like.
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(path.c_str(), &raw) == SQLITE_OK);
        const char* v1 = R"(
            CREATE TABLE cve (
                cve_id TEXT PRIMARY KEY, product TEXT NOT NULL, vendor TEXT,
                affected_below TEXT NOT NULL, fixed_in TEXT, severity TEXT NOT NULL,
                description TEXT NOT NULL, published TEXT, last_modified TEXT,
                source TEXT DEFAULT 'nvd');
            CREATE INDEX idx_cve_product ON cve(product);
            CREATE TABLE sync_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE schema_meta (store TEXT PRIMARY KEY, version INTEGER NOT NULL,
                                      upgraded_at TEXT);
            INSERT INTO cve (cve_id, product, vendor, affected_below, fixed_in, severity, description)
                VALUES ('CVE-2014-0160','openssl','openssl','1.0.1g','1.0.1g','CRITICAL','Heartbleed');
            INSERT INTO sync_meta (key, value) VALUES ('last_sync_time','2024-01-01T00:00:00Z');
            INSERT INTO schema_meta (store, version, upgraded_at)
                VALUES ('nvd_database', 1, '2024-01-01T00:00:00Z');
        )";
        char* err = nullptr;
        REQUIRE(sqlite3_exec(raw, v1, nullptr, nullptr, &err) == SQLITE_OK);
        sqlite3_free(err);
        sqlite3_close(raw);
    }

    // 2. Opening through NvdDatabase runs the v2 migration.
    NvdDatabase db(path);
    REQUIRE(db.is_open());

    // 3. The old flat rows are dropped (reconstructable from the next sync). The
    //    header table is empty and the old product no longer matches — proving
    //    the migration ran, not that it silently kept the v1 table.
    REQUIRE(db.total_cve_count() == 0);
    REQUIRE(db.match_inventory({{"openssl", "1.0.1f"}}).empty()); // would have matched under v1

    // 4. The sync cursor must NOT survive: v2 dropped the catalog, so a preserved
    //    last_sync_time would make the next sync incremental and the dropped rows
    //    would never be re-fetched (silently gone from /api/nvd/match forever). An
    //    empty cursor routes do_sync() to the full initial sync the upgrade docs
    //    promise ("fully reconstructable / self-healing").
    REQUIRE(db.get_meta("last_sync_time").empty());

    // 5. The reshaped schema is fully functional post-upgrade.
    db.upsert_cve(make_cve("CVE-2024-0001", "nginx", "1.25.0"));
    REQUIRE(db.total_cve_count() == 1);
    REQUIRE(db.match_inventory({{"nginx", "1.24.0"}}).size() == 1);
}

// ── Inventory Matching ───────────────────────────────────────────────────────

TEST_CASE("NvdDatabase: match_inventory finds vulnerable version", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));

    auto matches = db.match_inventory({{"openssl", "3.0.6"}});
    REQUIRE(matches.size() == 1);
    REQUIRE(matches[0].cve_id == "CVE-2024-0001");
    REQUIRE(matches[0].installed_version == "3.0.6");
    REQUIRE(matches[0].fixed_in == "3.0.7");
}

TEST_CASE("NvdDatabase: match_inventory skips fixed version", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));
    REQUIRE(db.match_inventory({{"openssl", "3.0.7"}}).empty());
}

TEST_CASE("NvdDatabase: match_inventory empty inventory", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "test", "1.0"));
    REQUIRE(db.match_inventory({}).empty());
}

TEST_CASE("NvdDatabase: match_inventory case-insensitive product", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));
    REQUIRE(db.match_inventory({{"OpenSSL", "3.0.6"}}).size() == 1);
}

TEST_CASE("NvdDatabase: match_inventory honours a version band", "[nvd][match]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-0007";
    rec.severity = "HIGH";
    rec.description = "band";
    rec.source = "nvd";
    CpeMatch cm;
    cm.cpe_product = "nginx";
    cm.version_start_including = "1.20.0";
    cm.version_end_excluding = "1.24.0";
    rec.matches.push_back(cm);
    db.upsert_cve(rec);

    REQUIRE(db.match_inventory({{"nginx", "1.22.0"}}).size() == 1);
    REQUIRE(db.match_inventory({{"nginx", "1.19.0"}}).empty()); // below start
    REQUIRE(db.match_inventory({{"nginx", "1.24.0"}}).empty()); // at exclusive end
}

TEST_CASE("NvdDatabase: multi-product CVE preserved (row-loss regression)", "[nvd][match]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-9999";
    rec.severity = "HIGH";
    rec.description = "multi-product";
    rec.source = "nvd";
    rec.matches.push_back(CpeMatch{.cpe_product = "producta", .version_end_excluding = "1.0"});
    rec.matches.push_back(CpeMatch{.cpe_product = "productb", .version_end_excluding = "2.0"});
    db.upsert_cve(rec);

    // Both products are independently matchable — the old INSERT OR REPLACE bug
    // kept only the last row and would fail one of these.
    REQUIRE(db.match_inventory({{"producta", "0.9"}}).size() == 1);
    REQUIRE(db.match_inventory({{"productb", "1.5"}}).size() == 1);
    REQUIRE(db.match_inventory({{"productb", "2.0"}}).empty());
    REQUIRE(db.total_cve_count() == 1);
}

TEST_CASE("NvdDatabase: re-upsert replaces the match set", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));
    REQUIRE(db.match_inventory({{"openssl", "3.0.6"}}).size() == 1);

    // Re-sync the same CVE with a different product; the old openssl row must go.
    db.upsert_cve(make_cve("CVE-2024-0001", "nginx", "1.25.0"));
    REQUIRE(db.match_inventory({{"openssl", "3.0.6"}}).empty());
    REQUIRE(db.match_inventory({{"nginx", "1.24.0"}}).size() == 1);
    REQUIRE(db.total_cve_count() == 1);
}

// ── NVD JSON Parsing ─────────────────────────────────────────────────────────

TEST_CASE("parse_response: keeps cpeMatch range fields", "[nvd][parse]") {
    NvdClient client;
    std::string json = R"({
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0001",
                "descriptions": [{"lang": "en", "value": "Test vuln"}],
                "published": "2024-01-01T00:00:00.000",
                "lastModified": "2024-01-02T00:00:00.000",
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [{
                            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "1.0.0",
                            "versionEndExcluding": "1.2.3"
                        }]
                    }]
                }]
            }
        }]
    })";

    auto result = client.parse_response(json);
    REQUIRE(result.total_results == 1);
    REQUIRE(result.records.size() == 1);
    REQUIRE(result.records[0].cve_id == "CVE-2024-0001");
    REQUIRE(result.records[0].description == "Test vuln");
    REQUIRE(result.records[0].source == "nvd");
    REQUIRE(result.records[0].matches.size() == 1);
    REQUIRE(result.records[0].matches[0].cpe_vendor == "vendor");
    REQUIRE(result.records[0].matches[0].cpe_product == "product");
    REQUIRE(result.records[0].matches[0].version_start_including == "1.0.0");
    REQUIRE(result.records[0].matches[0].version_end_excluding == "1.2.3");
}

TEST_CASE("parse_response: CVSS v3.1 severity extraction", "[nvd][parse]") {
    NvdClient client;
    std::string json = R"({
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0002",
                "descriptions": [{"lang": "en", "value": "Critical vuln"}],
                "metrics": { "cvssMetricV31": [{ "cvssData": { "baseSeverity": "CRITICAL" } }] }
            }
        }]
    })";
    auto result = client.parse_response(json);
    REQUIRE(result.records.size() == 1);
    REQUIRE(result.records[0].severity == "CRITICAL");
}

TEST_CASE("parse_response: CVSS v2 fallback", "[nvd][parse]") {
    NvdClient client;
    std::string json = R"({
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0003",
                "descriptions": [{"lang": "en", "value": "Old vuln"}],
                "metrics": { "cvssMetricV2": [{ "baseSeverity": "HIGH" }] }
            }
        }]
    })";
    auto result = client.parse_response(json);
    REQUIRE(result.records.size() == 1);
    REQUIRE(result.records[0].severity == "HIGH");
}

TEST_CASE("parse_response: empty vulnerabilities array", "[nvd][parse]") {
    NvdClient client;
    auto result = client.parse_response(R"({"totalResults": 0, "vulnerabilities": []})");
    REQUIRE(result.total_results == 0);
    REQUIRE(result.records.empty());
}

TEST_CASE("parse_response: malformed JSON", "[nvd][parse]") {
    NvdClient client;
    auto result = client.parse_response("this is not json");
    REQUIRE(result.records.empty());
    REQUIRE(result.total_results == 0);
}

TEST_CASE("parse_response: tracks latest lastModified", "[nvd][parse]") {
    NvdClient client;
    std::string json = R"({
        "totalResults": 2,
        "vulnerabilities": [
            {"cve": {"id": "CVE-2024-0001", "lastModified": "2024-01-01T00:00:00.000"}},
            {"cve": {"id": "CVE-2024-0002", "lastModified": "2024-06-15T12:00:00.000"}}
        ]
    })";
    auto result = client.parse_response(json);
    REQUIRE(result.last_modified_timestamp == "2024-06-15T12:00:00.000");
}

TEST_CASE("parse_response: multiple cpeMatch produce one record with many matches",
          "[nvd][parse]") {
    NvdClient client;
    std::string json = R"({
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0004",
                "descriptions": [{"lang": "en", "value": "Multi-product"}],
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [
                            {"criteria": "cpe:2.3:a:vendorA:productA:*:*:*:*:*:*:*:*", "versionEndExcluding": "1.0"},
                            {"criteria": "cpe:2.3:a:vendorB:productB:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0"}
                        ]
                    }]
                }]
            }
        }]
    })";

    auto result = client.parse_response(json);
    REQUIRE(result.records.size() == 1);
    REQUIRE(result.records[0].matches.size() == 2);
    REQUIRE(result.records[0].matches[0].cpe_product == "producta");
    REQUIRE(result.records[0].matches[1].cpe_product == "productb");
}

// ── Governance hardening round (c1735cd3 review) ─────────────────────────────

TEST_CASE("nvd_version_compare: attached letter-release is a patch, not pre-release",
          "[nvd][version]") {
    // Regression for cpp-expert S1: OpenSSL-style "1.0.2a" is a patch ABOVE
    // "1.0.2"; ranking single-letter a/b as pre-release flipped this and would
    // flip vulnerable<->fixed against a version bound.
    REQUIRE(nvd_version_compare("1.0.2a", "1.0.2") > 0);
    REQUIRE(nvd_version_compare("1.0.2b", "1.0.2a") > 0);
    REQUIRE(nvd_version_compare("1.0.2a", "1.0.2b") < 0);
    // Multi-letter pre-release words still rank as pre-release.
    REQUIRE(nvd_version_compare("1.0.0-dev", "1.0.0-alpha") < 0);
    REQUIRE(nvd_version_compare("1.0.0-pre", "1.0.0-rc") < 0);
    REQUIRE(nvd_version_compare("1.0.0-preview", "1.0.0") < 0);
}

TEST_CASE("nvd_version_compare: overflow-safe on huge numeric segments", "[nvd][version]") {
    // Digit runs far beyond a 64-bit integer must still order correctly (the
    // reason numeric_compare is string-length based, not stoll).
    REQUIRE(nvd_version_compare("99999999999999999999", "100000000000000000000") < 0);
    REQUIRE(nvd_version_compare("100000000000000000000", "99999999999999999999") > 0);
    REQUIRE(nvd_version_compare("007", "7") == 0); // leading zeros
}

TEST_CASE("nvd_version_in_range: bounds take precedence over exact when both set",
          "[nvd][range]") {
    // exact pinned to 1.2.3 but an end_excluding bound also present → bounds win.
    VersionRange r{"1.2.3", "", "", "", "9.9"};
    REQUIRE(nvd_version_in_range("1.2.4", r)); // in [,9.9) → vulnerable via bound
    REQUIRE_FALSE(nvd_version_in_range("9.9", r));
}

TEST_CASE("nvd_version_in_range: open-ended and both-inclusive bounds", "[nvd][range]") {
    REQUIRE(nvd_version_in_range("9.9", VersionRange{"", "2.0", "", "", ""}));      // [2.0, )
    REQUIRE_FALSE(nvd_version_in_range("1.0", VersionRange{"", "2.0", "", "", ""})); // below start
    VersionRange band{"", "1.0", "", "2.0", ""};                                    // [1.0, 2.0]
    REQUIRE(nvd_version_in_range("1.0", band));
    REQUIRE(nvd_version_in_range("2.0", band));
    REQUIRE_FALSE(nvd_version_in_range("2.1", band));
}

TEST_CASE("NvdDatabase: is_vulnerable=false rows are excluded from matches", "[nvd][match]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-8000";
    rec.severity = "HIGH";
    rec.description = "running-on platform node";
    rec.source = "nvd";
    rec.matches.push_back(
        CpeMatch{.cpe_product = "linux_kernel", .version_end_excluding = "9.9", .is_vulnerable = false});
    db.upsert_cve(rec);
    REQUIRE(db.match_inventory({{"linux_kernel", "1.0"}}).empty());
}

TEST_CASE("NvdDatabase: match_inventory skips empty name/version", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));
    // Empty fields are skipped; a valid item in the same batch still matches.
    auto m = db.match_inventory({{"", "1.0"}, {"openssl", ""}, {"openssl", "3.0.6"}});
    REQUIRE(m.size() == 1);
    REQUIRE(m[0].cve_id == "CVE-2024-0001");
}

TEST_CASE("NvdDatabase: LIKE metacharacters in name do not broaden the match", "[nvd][match]") {
    NvdDatabase db(":memory:");
    db.upsert_cve(make_cve("CVE-2024-0001", "openssl", "3.0.7"));
    // '%' must be treated literally (escaped), not as a wildcard that matches
    // "openssl". A literal "a%b" product is not in the DB → no match.
    REQUIRE(db.match_inventory({{"a%b", "1.0"}}).empty());
    REQUIRE(db.match_inventory({{"%", "1.0"}}).empty());
}

TEST_CASE("NvdDatabase: v2 migration is idempotent across reopen", "[nvd][db][migration]") {
    yuzu::test::TempDbFile tmp{std::string_view{"nvd-remigrate-"}};
    const std::string path = tmp.path.string();
    {
        NvdDatabase db(path);
        db.upsert_cve(make_cve("CVE-2024-0001", "nginx", "1.25.0"));
        REQUIRE(db.total_cve_count() == 1);
    }
    // Reopen: schema_meta already at v2, so migration 2 must NOT re-run / wipe.
    NvdDatabase db2(path);
    REQUIRE(db2.total_cve_count() == 1);
    REQUIRE(db2.match_inventory({{"nginx", "1.24.0"}}).size() == 1);
}

TEST_CASE("NvdDatabase: a failed upsert rolls back atomically (no partial state)",
          "[nvd][match]") {
    yuzu::test::TempDbFile tmp{std::string_view{"nvd-atomic-"}};
    const std::string path = tmp.path.string();

    NvdDatabase db(path);
    db.upsert_cve(make_cve("CVE-A", "openssl", "3.0.7"));
    REQUIRE(db.total_cve_count() == 1);

    // Force a mid-upsert failure by dropping cve_match out from under the store
    // via a second connection: the header INSERT succeeds, the cve_match DELETE
    // then fails to prepare → the whole CVE must ROLLBACK TO the savepoint, so
    // the new header must NOT survive (UP-1: no partial commit).
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(path.c_str(), &raw) == SQLITE_OK);
        REQUIRE(sqlite3_exec(raw, "DROP TABLE cve_match;", nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    db.upsert_cve(make_cve("CVE-B", "nginx", "1.25.0")); // must roll back
    REQUIRE(db.total_cve_count() == 1); // CVE-B header did not survive the rollback
}

// ── Rate-limit wait (regression for the #1867 first-request overflow) ─────────

TEST_CASE("nvd_rate_limit_wait: first request never waits (overflow regression)",
          "[nvd][ratelimit]") {
    using namespace std::chrono;
    const auto now = steady_clock::now();
    const auto interval = milliseconds(6000);
    // No prior request (nullopt) — the old time_point::min() sentinel overflowed
    // here and slept ~292 years; must be zero.
    REQUIRE(nvd_rate_limit_wait(std::nullopt, now, interval) == steady_clock::duration::zero());
}

TEST_CASE("nvd_rate_limit_wait: throttles within the interval, not after", "[nvd][ratelimit]") {
    using namespace std::chrono;
    const auto now = steady_clock::now();
    const auto interval = milliseconds(6000);

    // A request 1s ago → wait exactly the remaining 5s (pure function, deterministic).
    const auto w = nvd_rate_limit_wait(now - milliseconds(1000), now, interval);
    REQUIRE(duration_cast<milliseconds>(w).count() == 5000);

    // A request well outside the interval → no wait.
    REQUIRE(nvd_rate_limit_wait(now - seconds(30), now, interval) == steady_clock::duration::zero());
    // Exactly at the interval boundary → no wait.
    REQUIRE(nvd_rate_limit_wait(now - milliseconds(6000), now, interval) ==
            steady_clock::duration::zero());
}

TEST_CASE("nvd_rate_limit_wait: non-positive elapsed never waits (overflow-class guard)",
          "[nvd][ratelimit]") {
    using namespace std::chrono;
    const auto now = steady_clock::now();
    const auto interval = milliseconds(6000);
    // A `last` in the future (backwards/non-monotonic clock) must return zero, not
    // `interval - negative` — the defence against the ~292yr overflow class.
    REQUIRE(nvd_rate_limit_wait(now + milliseconds(10), now, interval) ==
            steady_clock::duration::zero());
    REQUIRE(nvd_rate_limit_wait(now + hours(1000000), now, interval) ==
            steady_clock::duration::zero());
    // elapsed == 0 (same instant) → no wait.
    REQUIRE(nvd_rate_limit_wait(now, now, interval) == steady_clock::duration::zero());
}
