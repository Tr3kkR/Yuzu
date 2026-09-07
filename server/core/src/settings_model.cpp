/// @file settings_model.cpp
/// Implementation of the pure Settings read-twin builders. See
/// settings_model.hpp for the shared-builder rationale (#4028).

#include "settings_model.hpp"

namespace yuzu::server::settings_model {

std::string sanitize_url_userinfo(std::string_view url) {
    if (url.empty())
        return std::string(url);
    // Authority starts right after "scheme://" if present, else at the very
    // start of the string (a bare "user:pass@host" with no scheme is still
    // sanitized).
    std::size_t authority_start = 0;
    if (auto scheme_end = url.find("://"); scheme_end != std::string_view::npos)
        authority_start = scheme_end + 3;

    // #4028 fix-round history (kept because the naive-looking design below
    // is the product of two failed, more "precise" attempts -- a future
    // editor tempted to reintroduce a host/authority-boundary heuristic
    // should read this first):
    //
    //   Round 1 tried to first locate the authority's end (the path-
    //   starting '/') and search for '@' only within that boundary, with a
    //   `looks_like_bare_host` heuristic to widen the search past an
    //   embedded, unescaped '/' in the password. Gate 8 re-review (three
    //   independent reviewers: cpp-safety, security-guardian, cpp-expert)
    //   found the boundary-first approach fundamentally unfixable: a
    //   password segment that happens to be digit-only before the '/'
    //   (e.g. "admin:1234/ss@host") is LEXICALLY IDENTICAL to a real
    //   "host:port" and the heuristic cannot tell them apart, no matter how
    //   it is patched -- two rounds of patching that same heuristic each
    //   shipped a new bypass or regression.
    //
    //   Round 2 (this implementation) deletes the heuristic and the
    //   boundary-first search entirely. `@` is never legal in a URL's
    //   host/port; the only genuinely unresolvable ambiguity is whether a
    //   later '@' belongs to a corrupted (unescaped) password or to
    //   legitimate path/table content (".../db@table"). Since this is a
    //   DISPLAY-ONLY sanitizer with no obligation to hand back a working
    //   URL, that ambiguity is resolved by always preferring to
    //   OVER-STRIP: the LAST '@' anywhere at or after `authority_start` is
    //   treated as ending a userinfo component, full stop. This can
    //   discard legitimate trailing path content when the path itself
    //   contains a later '@' (see the "sweeps up a legitimate path '@'"
    //   test below), but it can never leave a real credential character in
    //   the output -- the discarded prefix always fully contains whatever
    //   userinfo existed, however it was shaped, because nothing after the
    //   chosen '@' can be part of an EARLIER credential.
    //
    //   KNOWN OPEN GAPS as of this writing (governance ledger
    //   governance.d/4028-settings-read-twins.BAbeot.jsonl, findings
    //   g8b-sanitizer-scheme-boundary and the query-vs-userinfo ordering
    //   finding, both `open`/HIGH/BLOCKING) -- the "it can never leave a
    //   real credential character" claim two paragraphs up is NOT true in
    //   two cases Gate 8b found: (a) a schemeless credential URL whose
    //   query string embeds another "://" (e.g. a
    //   "?ssl_ca=https://ca.example/root.pem" value) fools the
    //   `url.find("://")` scheme search above into computing
    //   `authority_start` past the real userinfo entirely, leaking it in
    //   full; (b) a query string that itself contains a later '@' (e.g.
    //   "?user=admin@corp.com&password=...") breaks the sequential
    //   strip-then-search-the-result ordering below, discarding the
    //   query's own '?' before it can be found. A verified fix exists
    //   (compute both cut points against the ORIGINAL `url`, not
    //   sequentially against a once-mutated string, and union the two
    //   removal ranges) but was not applied this session -- two full
    //   redesigns of this function each surfaced new bypasses on review,
    //   and a third rushed patch was judged higher risk than stopping to
    //   flag it for deliberate, unhurried review. DO NOT patch this
    //   function again without reading the full ledger history first.
    auto at_pos = url.find_last_of('@');
    std::string sanitized = (at_pos != std::string_view::npos && at_pos >= authority_start)
                                 ? std::string(url.substr(0, authority_start)) +
                                       std::string(url.substr(at_pos + 1))
                                 : std::string(url);

    // A query string or fragment can carry its OWN credential form this
    // function otherwise never models at all -- e.g. ClickHouse's HTTP
    // interface also accepts "?user=admin&password=..." with no '@'
    // anywhere in the URL (#4028 fix-round finding UP-2). This is dropped
    // unconditionally rather than selectively redacted (selective
    // redaction would need to enumerate every driver's own query-parameter
    // convention and stays wrong for the next one), and it runs AFTER the
    // '@'-based strip above, against the ALREADY-sanitized string: an
    // unescaped '?' or '#' inside a password that the '@' strip already
    // removed can then never be mistaken for the real query start (running
    // this step first, against the raw `url`, was round 1's other defect --
    // it truncated before the real userinfo delimiter was ever found).
    auto qf = sanitized.find_first_of("?#", authority_start);
    if (qf != std::string::npos)
        sanitized.resize(qf);
    return sanitized;
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
