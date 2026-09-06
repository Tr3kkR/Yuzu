/// @file settings_model.cpp
/// Implementation of the pure Settings read-twin builders. See
/// settings_model.hpp for the shared-builder rationale (#4028).

#include "settings_model.hpp"

#include <algorithm>
#include <cctype>

namespace yuzu::server::settings_model {

namespace {

// True if `s` looks like a bare "host" or "host:port" with no userinfo --
// i.e. either no ':' at all, or the LAST ':' is followed only by digits (a
// plausible port). Real hosts never contain '@' or an internal '/'; this is
// the signal `sanitize_url_userinfo` uses below to tell "an unencoded '/'
// inside the userinfo landed here" (looks_like_bare_host == false, keep
// searching for the real '@') apart from "this genuinely is the host, the
// '/' right after it starts the path" (looks_like_bare_host == true, a
// later '@' -- if any -- belongs to the path, not to credentials; #4028
// fix-round finding UP-1's ".../db@table` regression case).
bool looks_like_bare_host(std::string_view s) {
    auto colon = s.find_last_of(':');
    if (colon == std::string_view::npos)
        return true;
    auto port = s.substr(colon + 1);
    return !port.empty() &&
           std::all_of(port.begin(), port.end(),
                       [](unsigned char c) { return std::isdigit(c) != 0; });
}

}  // namespace

std::string sanitize_url_userinfo(std::string_view url) {
    if (url.empty())
        return std::string(url);
    // Authority starts right after "scheme://" if present, else at the very
    // start of the string (a bare "user:pass@host" with no scheme is still
    // sanitized).
    std::size_t authority_start = 0;
    if (auto scheme_end = url.find("://"); scheme_end != std::string_view::npos)
        authority_start = scheme_end + 3;

    // A query string or fragment can carry its OWN credential form this
    // function otherwise never models at all -- e.g. ClickHouse's HTTP
    // interface also accepts "?user=admin&password=..." with no '@'
    // anywhere in the URL (#4028 fix-round finding UP-2). This is a
    // display-only sanitizer with no obligation to hand back a working
    // URL, so query string and fragment are dropped unconditionally rather
    // than selectively redacted (selective redaction would need to
    // enumerate every driver's own query-parameter convention and stays
    // wrong for the next one).
    auto qf = url.find_first_of("?#", authority_start);
    std::string base(url.substr(0, qf == std::string_view::npos ? url.size() : qf));

    auto slash = base.find('/', authority_start);
    auto authority_end = (slash == std::string::npos) ? base.size() : slash;

    // Userinfo delimiter is the LAST '@' before authority_end, not the
    // first: a password containing an unescaped '@' (e.g. "p@ss") left the
    // first-'@' search stop mid-password, leaking the remainder verbatim
    // (original sec-H1 report).
    auto at_pos = base.find_last_of('@');
    if (at_pos != std::string::npos && at_pos < authority_end && at_pos >= authority_start)
        return base.substr(0, authority_start) + base.substr(at_pos + 1);

    // No '@' found before the naive authority boundary. Either there is
    // genuinely no userinfo (the common case -- e.g. ".../db@table", where
    // "host:9000" before the '/' looks like a bare host and this branch
    // must NOT fire), or the naive boundary itself is wrong: a password
    // containing an unescaped '/' (e.g. "pa/ss") makes the FIRST '/' land
    // inside the userinfo, well before the real '@' (original UP-1
    // report), which is exactly what `looks_like_bare_host` distinguishes.
    // If what precedes the '/' does NOT look like a plausible host[:port],
    // widen the search for '@' past that '/' and, if found, treat
    // everything up to it as userinfo.
    if (slash != std::string::npos &&
        !looks_like_bare_host(base.substr(authority_start, slash - authority_start))) {
        if (auto wider_at = base.find('@', slash); wider_at != std::string::npos)
            return base.substr(0, authority_start) + base.substr(wider_at + 1);
    }

    return base; // no userinfo present in the authority component
}

nlohmann::json build_tls_settings(const Config& cfg) {
    nlohmann::json j;
    j["enabled"] = cfg.tls_enabled;
    j["server_cert_path"] = cfg.tls_server_cert.string();
    j["server_key_path"] = cfg.tls_server_key.string();
    j["ca_cert_path"] = cfg.tls_ca_cert.string();
    j["insecure_skip_client_verify"] = cfg.insecure_skip_client_verify;
    j["mgmt_server_cert_path"] = cfg.mgmt_tls_server_cert.string();
    j["mgmt_server_key_path"] = cfg.mgmt_tls_server_key.string();
    j["mgmt_ca_cert_path"] = cfg.mgmt_tls_ca_cert.string();
    return j;
}

nlohmann::json build_https_settings(const Config& cfg) {
    nlohmann::json j;
    j["enabled"] = cfg.https_enabled;
    j["port"] = cfg.https_port;
    j["cert_path"] = cfg.https_cert_path.string();
    j["key_path"] = cfg.https_key_path.string();
    j["redirect"] = cfg.https_redirect;
    return j;
}

nlohmann::json build_gateway_settings(const Config& cfg, bool gateway_enabled,
                                      std::size_t active_sessions) {
    nlohmann::json j;
    j["enabled"] = gateway_enabled;
    j["listen_address"] = gateway_enabled ? cfg.gateway_upstream_address : std::string{};
    j["gateway_mode"] = gateway_enabled && cfg.gateway_mode;
    j["active_sessions"] =
        gateway_enabled ? static_cast<std::int64_t>(active_sessions) : std::int64_t{0};
    return j;
}

nlohmann::json build_server_config_settings(const Config& cfg) {
    nlohmann::json j;
    j["agent_grpc_address"] = cfg.listen_address;
    j["management_grpc_address"] = cfg.management_address;
    j["web_address"] = cfg.web_address;
    j["web_port"] = cfg.web_port;
    j["session_timeout_seconds"] = static_cast<std::int64_t>(cfg.session_timeout.count());
    j["max_agents"] = static_cast<std::int64_t>(cfg.max_agents);
    j["auth_config_path"] = cfg.auth_config_path.string();
    j["rate_limit_per_ip"] = cfg.rate_limit;
    j["login_rate_limit_per_ip"] = cfg.login_rate_limit;
    j["ota_max_concurrent_per_peer"] = cfg.ota_max_concurrent_per_peer;
    j["ota_rate_refill_per_min"] = cfg.ota_rate_refill_per_min;
    j["ota_rate_capacity"] = cfg.ota_rate_capacity;
    j["ota_max_concurrent_total"] = cfg.ota_max_concurrent_total;
    j["ota_max_peers_tracked"] = cfg.ota_max_peers_tracked;
    j["ota_transfer_deadline_secs"] = cfg.ota_transfer_deadline_secs;
    j["ota_chunk_write_deadline_secs"] = cfg.ota_chunk_write_deadline_secs;
    j["grpc_max_concurrent_streams"] = cfg.grpc_max_concurrent_streams;
    j["grpc_max_resource_memory_mb"] = cfg.grpc_max_resource_memory_mb;
    return j;
}

nlohmann::json build_mcp_settings(const Config& cfg) {
    nlohmann::json j;
    const bool mcp_enabled = !cfg.mcp_disable;
    j["enabled"] = mcp_enabled;
    j["read_only"] = cfg.mcp_read_only;
    // Mirrors render_mcp_fragment()'s own URL derivation exactly (settings_routes.cpp)
    // so the two surfaces can never disagree on the endpoint they advertise.
    const std::string proto = cfg.https_enabled ? "https" : "http";
    const std::string host = cfg.web_address == "0.0.0.0" ? "localhost" : cfg.web_address;
    const int port = cfg.https_enabled ? cfg.https_port : cfg.web_port;
    j["endpoint_url"] = proto + "://" + host + ":" + std::to_string(port) + "/mcp/v1/";
    return j;
}

nlohmann::json build_data_retention_settings(const Config& cfg) {
    nlohmann::json j;
    j["response_retention_days"] = cfg.response_retention_days;
    j["audit_retention_days"] = cfg.audit_retention_days;
    return j;
}

nlohmann::json build_analytics_settings(const Config& cfg) {
    nlohmann::json j;
    j["enabled"] = cfg.analytics_enabled;
    j["drain_interval_seconds"] = cfg.analytics_drain_interval_seconds;
    j["batch_size"] = cfg.analytics_batch_size;
    const bool ch_configured = !cfg.clickhouse_url.empty();
    j["clickhouse_configured"] = ch_configured;
    // #4028 Evidence: the URL, not just the discrete password field, can
    // carry embedded credentials (clickhouse://user:pass@host:port/db) —
    // always sanitize, never emit cfg.clickhouse_url raw.
    j["clickhouse_url"] = ch_configured ? sanitize_url_userinfo(cfg.clickhouse_url) : std::string{};
    j["clickhouse_database"] = cfg.clickhouse_database;
    j["clickhouse_table"] = cfg.clickhouse_table;
    j["clickhouse_username"] = cfg.clickhouse_username;
    // The raw password is intentionally never read into `j` — only whether
    // it is set. cfg.clickhouse_password itself is not referenced below.
    j["clickhouse_password_set"] = !cfg.clickhouse_password.empty();
    j["jsonl_export_path"] = cfg.analytics_jsonl_path.string();
    return j;
}

nlohmann::json build_plugin_signing_settings(
    bool required,
    const std::optional<std::expected<plugin_signing::TrustBundleStats, std::string>>& bundle,
    std::string_view trust_bundle_pem) {
    nlohmann::json j;
    const bool enabled = bundle.has_value() && bundle->has_value();
    j["enabled"] = enabled;
    j["required"] = required;
    if (enabled) {
        const auto& stats = bundle->value();
        j["cert_count"] = stats.cert_count;
        j["sha256"] = stats.sha256_hex;
        j["subjects"] = stats.subjects;
    } else {
        j["cert_count"] = 0;
        j["sha256"] = "";
        j["subjects"] = nlohmann::json::array();
    }
    const bool unreadable = bundle.has_value() && !bundle->has_value();
    j["bundle_unreadable"] = unreadable;
    if (unreadable)
        j["bundle_error"] = bundle->error();
    if (!trust_bundle_pem.empty())
        j["trust_bundle_pem"] = trust_bundle_pem;
    return j;
}

} // namespace yuzu::server::settings_model
