/**
 * test_nvd.cpp — Unit tests for NVD database, version comparison, and JSON parsing
 *
 * Covers: compare_versions(), NvdDatabase CRUD + match_inventory(),
 *         NvdClient::parse_response().
 */

#include "nvd_db.hpp"
#include "nvd_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using namespace yuzu::server;

// ── Version Comparison ───────────────────────────────────────────────────────

TEST_CASE("compare_versions: equal versions", "[nvd][version]") {
    REQUIRE(compare_versions("1.0.0", "1.0.0") == 0);
}

TEST_CASE("compare_versions: less than", "[nvd][version]") {
    REQUIRE(compare_versions("1.0.0", "2.0.0") < 0);
}

TEST_CASE("compare_versions: greater than", "[nvd][version]") {
    REQUIRE(compare_versions("2.0.0", "1.0.0") > 0);
}

TEST_CASE("compare_versions: patch level", "[nvd][version]") {
    REQUIRE(compare_versions("1.2.3", "1.2.4") < 0);
    REQUIRE(compare_versions("1.2.4", "1.2.3") > 0);
}

TEST_CASE("compare_versions: numeric not lexicographic", "[nvd][version]") {
    REQUIRE(compare_versions("1.10.0", "1.9.0") > 0);
    REQUIRE(compare_versions("1.9.0", "1.10.0") < 0);
}

TEST_CASE("compare_versions: missing segments", "[nvd][version]") {
    // Missing segments treated as 0
    REQUIRE(compare_versions("1.0", "1.0.0") == 0);
    REQUIRE(compare_versions("1", "1.0.0") == 0);
}

TEST_CASE("compare_versions: pre-release suffix", "[nvd][version]") {
    // "beta" < "rc" in string comparison when numeric comparison fails
    REQUIRE(compare_versions("1.0.0-beta", "1.0.0-rc") < 0);
}

TEST_CASE("compare_versions: empty strings", "[nvd][version]") {
    REQUIRE(compare_versions("", "") == 0);
    REQUIRE(compare_versions("1.0", "") > 0);
    REQUIRE(compare_versions("", "1.0") < 0);
}

// ── NvdDatabase ──────────────────────────────────────────────────────────────

TEST_CASE("NvdDatabase: open in-memory", "[nvd][db]") {
    NvdDatabase db(":memory:");
    REQUIRE(db.is_open());
}

TEST_CASE("NvdDatabase: upsert and count", "[nvd][db]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-0001";
    rec.product = "openssl";
    rec.vendor = "openssl";
    rec.affected_below = "3.0.7";
    rec.severity = "HIGH";
    rec.description = "Test vulnerability";
    rec.source = "nvd";

    db.upsert_cve(rec);
    REQUIRE(db.total_cve_count() == 1);
}

TEST_CASE("NvdDatabase: upsert batch", "[nvd][db]") {
    NvdDatabase db(":memory:");
    std::vector<CveRecord> records;
    for (int i = 0; i < 5; ++i) {
        CveRecord rec;
        rec.cve_id = "CVE-2024-000" + std::to_string(i);
        rec.product = "test";
        rec.vendor = "test";
        rec.severity = "MEDIUM";
        rec.source = "nvd";
        records.push_back(std::move(rec));
    }

    db.upsert_cves(records);
    REQUIRE(db.total_cve_count() == 5);
}

TEST_CASE("NvdDatabase: upsert same ID replaces", "[nvd][db]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-0001";
    rec.product = "test";
    rec.severity = "LOW";
    rec.source = "nvd";

    db.upsert_cve(rec);
    rec.severity = "CRITICAL";
    db.upsert_cve(rec);

    REQUIRE(db.total_cve_count() == 1);
}

TEST_CASE("NvdDatabase: metadata round-trip", "[nvd][db]") {
    NvdDatabase db(":memory:");
    db.set_meta("last_sync", "2024-01-01T00:00:00Z");
    REQUIRE(db.get_meta("last_sync") == "2024-01-01T00:00:00Z");
}

TEST_CASE("NvdDatabase: get_meta returns empty for missing key", "[nvd][db]") {
    NvdDatabase db(":memory:");
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

// ── Inventory Matching ───────────────────────────────────────────────────────

TEST_CASE("NvdDatabase: match_inventory finds vulnerable version", "[nvd][match]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-0001";
    rec.product = "openssl";
    rec.vendor = "openssl";
    rec.affected_below = "3.0.7";
    rec.severity = "HIGH";
    rec.source = "nvd";
    db.upsert_cve(rec);

    std::vector<SoftwareItem> inventory = {{"openssl", "3.0.6"}};
    auto matches = db.match_inventory(inventory);
    REQUIRE(matches.size() == 1);
    REQUIRE(matches[0].cve_id == "CVE-2024-0001");
    REQUIRE(matches[0].installed_version == "3.0.6");
}

TEST_CASE("NvdDatabase: match_inventory skips fixed version", "[nvd][match]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-0001";
    rec.product = "openssl";
    rec.vendor = "openssl";
    rec.affected_below = "3.0.7";
    rec.severity = "HIGH";
    rec.source = "nvd";
    db.upsert_cve(rec);

    std::vector<SoftwareItem> inventory = {{"openssl", "3.0.7"}};
    auto matches = db.match_inventory(inventory);
    REQUIRE(matches.empty());
}

TEST_CASE("NvdDatabase: match_inventory empty inventory", "[nvd][match]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-0001";
    rec.product = "test";
    rec.affected_below = "1.0";
    rec.source = "nvd";
    db.upsert_cve(rec);

    auto matches = db.match_inventory({});
    REQUIRE(matches.empty());
}

TEST_CASE("NvdDatabase: match_inventory case-insensitive product", "[nvd][match]") {
    NvdDatabase db(":memory:");
    CveRecord rec;
    rec.cve_id = "CVE-2024-0001";
    rec.product = "openssl";  // lowercase in DB
    rec.affected_below = "3.0.7";
    rec.source = "nvd";
    db.upsert_cve(rec);

    // Inventory uses mixed case — should still match
    std::vector<SoftwareItem> inventory = {{"OpenSSL", "3.0.6"}};
    auto matches = db.match_inventory(inventory);
    REQUIRE(matches.size() == 1);
}

// ── NVD JSON Parsing ─────────────────────────────────────────────────────────

TEST_CASE("parse_response: minimal valid JSON", "[nvd][parse]") {
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
    REQUIRE(result.records[0].product == "product");
    REQUIRE(result.records[0].vendor == "vendor");
    REQUIRE(result.records[0].affected_below == "1.2.3");
    REQUIRE(result.records[0].description == "Test vuln");
    REQUIRE(result.records[0].source == "nvd");
}

TEST_CASE("parse_response: CVSS v3.1 severity extraction", "[nvd][parse]") {
    NvdClient client;
    std::string json = R"({
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0002",
                "descriptions": [{"lang": "en", "value": "Critical vuln"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": { "baseSeverity": "CRITICAL" }
                    }]
                }
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
                "metrics": {
                    "cvssMetricV2": [{ "baseSeverity": "HIGH" }]
                }
            }
        }]
    })";

    auto result = client.parse_response(json);
    REQUIRE(result.records.size() == 1);
    REQUIRE(result.records[0].severity == "HIGH");
}

TEST_CASE("parse_response: empty vulnerabilities array", "[nvd][parse]") {
    NvdClient client;
    std::string json = R"({"totalResults": 0, "vulnerabilities": []})";

    auto result = client.parse_response(json);
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

TEST_CASE("parse_response: multiple CPE nodes produce multiple records", "[nvd][parse]") {
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
    REQUIRE(result.records.size() == 2);
    REQUIRE(result.records[0].product == "producta");
    REQUIRE(result.records[1].product == "productb");
}
