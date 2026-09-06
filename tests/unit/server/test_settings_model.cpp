/**
 * test_settings_model.cpp — pure unit tests for the shared Settings
 * read-twin builders (#4028, api-parity programme #2146,
 * docs/api-twin-recipe.md §1). These functions take only a `Config&` (plus
 * the handful of non-Config inputs a fragment needs) and return the JSON
 * "data" payload both `settings_routes.cpp`'s HTML fragment renderers and
 * its `GET /api/v1/settings/...` REST handlers consume — so testing them here
 * directly (no httplib, no TestRouteSink) covers the data-shape contract
 * both surfaces share.
 *
 * The ClickHouse URL userinfo-sanitization tests below are the regression
 * coverage for the security fix #4028's Evidence section flags: the
 * analytics builder must never let embedded URL credentials reach either
 * surface, only the discrete clickhouse_password_set bool.
 */

#include "settings_model.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/server/server.hpp>

using namespace yuzu::server;
namespace sm = yuzu::server::settings_model;

// ── sanitize_url_userinfo ────────────────────────────────────────────────

TEST_CASE("sanitize_url_userinfo strips user:pass@ from a scheme URL",
          "[settings][settings_model]") {
    CHECK(sm::sanitize_url_userinfo("clickhouse://admin:s3cr3t@host:9000/yuzu") ==
          "clickhouse://host:9000/yuzu");
}

TEST_CASE("sanitize_url_userinfo strips a bare user@ with no password",
          "[settings][settings_model]") {
    CHECK(sm::sanitize_url_userinfo("clickhouse://admin@host:9000/yuzu") ==
          "clickhouse://host:9000/yuzu");
}

TEST_CASE("sanitize_url_userinfo leaves a URL with no userinfo unchanged",
          "[settings][settings_model]") {
    CHECK(sm::sanitize_url_userinfo("clickhouse://host:9000/yuzu") ==
          "clickhouse://host:9000/yuzu");
}

TEST_CASE("sanitize_url_userinfo handles a schemeless authority",
          "[settings][settings_model]") {
    // No "://" at all — the whole prefix up to the first '/' is the
    // authority, so userinfo there must still be stripped.
    CHECK(sm::sanitize_url_userinfo("admin:s3cr3t@host:9000/yuzu") == "host:9000/yuzu");
}

TEST_CASE("sanitize_url_userinfo does not touch an '@' inside the path",
          "[settings][settings_model]") {
    // An '@' appearing only after the first '/' is not authority userinfo —
    // must not be mistaken for one and stripped.
    CHECK(sm::sanitize_url_userinfo("clickhouse://host:9000/db@table") ==
          "clickhouse://host:9000/db@table");
}

TEST_CASE("sanitize_url_userinfo handles an empty string", "[settings][settings_model]") {
    CHECK(sm::sanitize_url_userinfo("") == "");
}

// ── build_analytics_settings — the security-fix regression coverage ─────

TEST_CASE("build_analytics_settings sanitizes the ClickHouse URL and never emits the raw password",
          "[settings][settings_model][security]") {
    Config cfg;
    cfg.analytics_enabled = true;
    cfg.analytics_drain_interval_seconds = 10;
    cfg.analytics_batch_size = 100;
    cfg.clickhouse_url = "clickhouse://admin:s3cr3t@host:9000/yuzu";
    cfg.clickhouse_database = "yuzu";
    cfg.clickhouse_table = "yuzu_events";
    cfg.clickhouse_username = "admin";
    cfg.clickhouse_password = "s3cr3t";

    auto j = sm::build_analytics_settings(cfg);

    CHECK(j.at("enabled").get<bool>() == true);
    CHECK(j.at("clickhouse_configured").get<bool>() == true);
    CHECK(j.at("clickhouse_url").get<std::string>() == "clickhouse://host:9000/yuzu");
    CHECK(j.at("clickhouse_password_set").get<bool>() == true);

    // The raw secret must not appear ANYWHERE in the serialized payload —
    // not just absent from a named field.
    auto dumped = j.dump();
    CHECK(dumped.find("s3cr3t") == std::string::npos);
    // The field itself must not exist at all (not even redacted-empty).
    CHECK(!j.contains("clickhouse_password"));
}

TEST_CASE("build_analytics_settings reports not-configured and password-unset when both are empty",
          "[settings][settings_model]") {
    Config cfg;
    cfg.clickhouse_url.clear();
    cfg.clickhouse_password.clear();

    auto j = sm::build_analytics_settings(cfg);

    CHECK(j.at("clickhouse_configured").get<bool>() == false);
    CHECK(j.at("clickhouse_url").get<std::string>().empty());
    CHECK(j.at("clickhouse_password_set").get<bool>() == false);
}

// ── build_tls_settings / build_https_settings ────────────────────────────

TEST_CASE("build_tls_settings reflects Config verbatim", "[settings][settings_model]") {
    Config cfg;
    cfg.tls_enabled = true;
    cfg.tls_server_cert = "/etc/yuzu/certs/server.pem";
    cfg.tls_server_key = "/etc/yuzu/certs/server.key";
    cfg.tls_ca_cert = "/etc/yuzu/certs/ca.pem";
    cfg.insecure_skip_client_verify = true;

    auto j = sm::build_tls_settings(cfg);

    CHECK(j.at("enabled").get<bool>() == true);
    CHECK(j.at("server_cert_path").get<std::string>() == "/etc/yuzu/certs/server.pem");
    CHECK(j.at("server_key_path").get<std::string>() == "/etc/yuzu/certs/server.key");
    CHECK(j.at("ca_cert_path").get<std::string>() == "/etc/yuzu/certs/ca.pem");
    CHECK(j.at("insecure_skip_client_verify").get<bool>() == true);
    // Unset management overrides serialize as empty strings, not omitted.
    CHECK(j.at("mgmt_server_cert_path").get<std::string>().empty());
}

TEST_CASE("build_https_settings reflects Config verbatim", "[settings][settings_model]") {
    Config cfg;
    cfg.https_enabled = true;
    cfg.https_port = 8443;
    cfg.https_redirect = false;

    auto j = sm::build_https_settings(cfg);

    CHECK(j.at("enabled").get<bool>() == true);
    CHECK(j.at("port").get<int>() == 8443);
    CHECK(j.at("redirect").get<bool>() == false);
}

// ── build_gateway_settings ────────────────────────────────────────────────

TEST_CASE("build_gateway_settings defaults every field when disabled",
          "[settings][settings_model]") {
    Config cfg;
    cfg.gateway_upstream_address = "0.0.0.0:50053";
    cfg.gateway_mode = true;

    auto j = sm::build_gateway_settings(cfg, /*gateway_enabled=*/false, /*active_sessions=*/5);

    CHECK(j.at("enabled").get<bool>() == false);
    CHECK(j.at("listen_address").get<std::string>().empty());
    CHECK(j.at("gateway_mode").get<bool>() == false);
    CHECK(j.at("active_sessions").get<std::int64_t>() == 0);
}

TEST_CASE("build_gateway_settings reports live state when enabled", "[settings][settings_model]") {
    Config cfg;
    cfg.gateway_upstream_address = "0.0.0.0:50053";
    cfg.gateway_mode = true;

    auto j = sm::build_gateway_settings(cfg, /*gateway_enabled=*/true, /*active_sessions=*/5);

    CHECK(j.at("enabled").get<bool>() == true);
    CHECK(j.at("listen_address").get<std::string>() == "0.0.0.0:50053");
    CHECK(j.at("gateway_mode").get<bool>() == true);
    CHECK(j.at("active_sessions").get<std::int64_t>() == 5);
}

// ── build_mcp_settings ────────────────────────────────────────────────────

TEST_CASE("build_mcp_settings derives an https endpoint URL when HTTPS is enabled",
          "[settings][settings_model]") {
    Config cfg;
    cfg.mcp_disable = false;
    cfg.mcp_read_only = true;
    cfg.https_enabled = true;
    cfg.https_port = 8443;
    cfg.web_address = "0.0.0.0";
    cfg.web_port = 8080;

    auto j = sm::build_mcp_settings(cfg);

    CHECK(j.at("enabled").get<bool>() == true);
    CHECK(j.at("read_only").get<bool>() == true);
    CHECK(j.at("endpoint_url").get<std::string>() == "https://localhost:8443/mcp/v1/");
}

TEST_CASE("build_mcp_settings derives an http endpoint URL when HTTPS is disabled and enabled reflects mcp_disable",
          "[settings][settings_model]") {
    Config cfg;
    cfg.mcp_disable = true;
    cfg.https_enabled = false;
    cfg.web_address = "127.0.0.1";
    cfg.web_port = 8080;

    auto j = sm::build_mcp_settings(cfg);

    CHECK(j.at("enabled").get<bool>() == false); // mcp_disable=true -> enabled=false
    CHECK(j.at("endpoint_url").get<std::string>() == "http://127.0.0.1:8080/mcp/v1/");
}

// ── build_data_retention_settings / build_server_config_settings ────────

TEST_CASE("build_data_retention_settings reflects Config verbatim", "[settings][settings_model]") {
    Config cfg;
    cfg.response_retention_days = 90;
    cfg.audit_retention_days = 365;

    auto j = sm::build_data_retention_settings(cfg);

    CHECK(j.at("response_retention_days").get<int>() == 90);
    CHECK(j.at("audit_retention_days").get<int>() == 365);
}

TEST_CASE("build_server_config_settings reflects Config verbatim", "[settings][settings_model]") {
    Config cfg;
    cfg.listen_address = "0.0.0.0:50051";
    cfg.management_address = "0.0.0.0:50052";
    cfg.web_address = "127.0.0.1";
    cfg.web_port = 8080;
    cfg.max_agents = 12345;
    cfg.rate_limit = 100;

    auto j = sm::build_server_config_settings(cfg);

    CHECK(j.at("agent_grpc_address").get<std::string>() == "0.0.0.0:50051");
    CHECK(j.at("management_grpc_address").get<std::string>() == "0.0.0.0:50052");
    CHECK(j.at("web_address").get<std::string>() == "127.0.0.1");
    CHECK(j.at("web_port").get<int>() == 8080);
    CHECK(j.at("max_agents").get<std::int64_t>() == 12345);
    CHECK(j.at("rate_limit_per_ip").get<int>() == 100);
}

// ── build_plugin_signing_settings ─────────────────────────────────────────

TEST_CASE("build_plugin_signing_settings reports disabled+empty when no bundle is on disk",
          "[settings][settings_model]") {
    auto j = sm::build_plugin_signing_settings(/*required=*/false, /*bundle=*/std::nullopt);

    CHECK(j.at("enabled").get<bool>() == false);
    CHECK(j.at("required").get<bool>() == false);
    CHECK(j.at("cert_count").get<int>() == 0);
    CHECK(j.at("sha256").get<std::string>().empty());
    CHECK(j.at("subjects").get<std::vector<std::string>>().empty());
    CHECK(j.at("bundle_unreadable").get<bool>() == false);
    CHECK(!j.contains("bundle_error"));
    // trust_bundle_pem defaults empty -> omitted (the fragment/settings-twin shape).
    CHECK(!j.contains("trust_bundle_pem"));
}

TEST_CASE("build_plugin_signing_settings reports the bundle stats when present",
          "[settings][settings_model]") {
    plugin_signing::TrustBundleStats stats;
    stats.cert_count = 2;
    stats.sha256_hex = "deadbeef";
    stats.subjects = {"CN=Yuzu Plugin Signer"};
    std::optional<std::expected<plugin_signing::TrustBundleStats, std::string>> bundle = stats;

    auto j = sm::build_plugin_signing_settings(/*required=*/true, bundle);

    CHECK(j.at("enabled").get<bool>() == true);
    CHECK(j.at("required").get<bool>() == true);
    CHECK(j.at("cert_count").get<int>() == 2);
    CHECK(j.at("sha256").get<std::string>() == "deadbeef");
    CHECK(j.at("subjects").get<std::vector<std::string>>() ==
          std::vector<std::string>{"CN=Yuzu Plugin Signer"});
    CHECK(j.at("bundle_unreadable").get<bool>() == false);
}

TEST_CASE("build_plugin_signing_settings reports bundle_unreadable and the error message",
          "[settings][settings_model]") {
    std::optional<std::expected<plugin_signing::TrustBundleStats, std::string>> bundle =
        std::unexpected(std::string("missing PEM begin/end markers"));

    auto j = sm::build_plugin_signing_settings(/*required=*/false, bundle);

    CHECK(j.at("enabled").get<bool>() == false);
    CHECK(j.at("bundle_unreadable").get<bool>() == true);
    CHECK(j.at("bundle_error").get<std::string>() == "missing PEM begin/end markers");
}

TEST_CASE("build_plugin_signing_settings emits trust_bundle_pem only when explicitly passed",
          "[settings][settings_model]") {
    // The plugin-policy route (its ONLY caller with a non-empty pem — see
    // the builder's own doc comment) is the superset; the fragment/other
    // callers pass an empty string so the field is omitted for them.
    auto j_without = sm::build_plugin_signing_settings(false, std::nullopt);
    CHECK(!j_without.contains("trust_bundle_pem"));

    auto j_with = sm::build_plugin_signing_settings(false, std::nullopt, "-----BEGIN...-----");
    REQUIRE(j_with.contains("trust_bundle_pem"));
    CHECK(j_with.at("trust_bundle_pem").get<std::string>() == "-----BEGIN...-----");
}
