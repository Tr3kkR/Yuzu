#include "ca_routes.hpp"

#include "rest_a4_envelope.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cctype>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

using detail::error_json_a4;
using detail::make_correlation_id;

constexpr const char* kJson = "application/json";
constexpr std::size_t kMaxRevokeBody = 64 * 1024; // bound the revoke POST body

int clamp_int(const httplib::Request& req, const char* key, int def, int lo, int hi) {
    auto it = req.params.find(key);
    if (it == req.params.end())
        return def;
    int v = def;
    try {
        v = std::stoi(it->second);
    } catch (...) {
        return def;
    }
    if (v < lo)
        v = lo;
    if (v > hi)
        v = hi;
    return v;
}

} // namespace

void CaRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                               CaStore* ca_store, PublishCrlFn publish_crl_fn) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn), ca_store,
                    std::move(publish_crl_fn));
}

void CaRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                               CaStore* ca_store, PublishCrlFn publish_crl_fn) {
    (void)auth_fn; // principal is resolved inside audit_fn/perm_fn from the request
    spdlog::info("CA routes: registering /api/v1/ca/*");

    // ── GET /api/v1/ca/root ── PUBLIC: the CA root certificate (PEM). ─────────
    // Public by definition — clients/browsers need it to trust the install, and
    // it is already presented in the TLS handshake.
    sink.Get("/api/v1/ca/root", [ca_store](const httplib::Request&, httplib::Response& res) {
        if (!ca_store || !ca_store->is_open()) {
            res.status = 503;
            res.set_content(error_json_a4(503, "CA not available", make_correlation_id()), kJson);
            return;
        }
        auto root = ca_store->get_root();
        if (!root) {
            res.status = 404;
            res.set_content(error_json_a4(404, "no CA root", make_correlation_id(),
                                          "the server has not generated or imported a CA"),
                            kJson);
            return;
        }
        // Hermes L7: offer as a download (operators trust this file) + allow
        // day-long caching — the root cert is stable for the CA's 10-year life.
        res.set_header("Content-Disposition", "attachment; filename=\"yuzu-ca.pem\"");
        res.set_header("Cache-Control", "public, max-age=86400");
        res.set_content(root->cert_pem, "application/x-pem-file");
    });

    // ── GET /api/v1/ca/crl ── PUBLIC: the current CRL (DER). ──────────────────
    // Serves the latest PUBLISHED CRL (cheap, DoS-safe for a public endpoint —
    // we do NOT rebuild+sign on every request); builds one on first access only.
    // Revocation republishes (see /revoke), so the served CRL stays current.
    sink.Get("/api/v1/ca/crl", [ca_store](const httplib::Request&, httplib::Response& res) {
                if (!ca_store || !ca_store->is_open()) {
                    res.status = 503;
                    res.set_content(error_json_a4(503, "CA not available", make_correlation_id()),
                                    kJson);
                    return;
                }
                // Hermes M1: serve ONLY the already-published CRL — never build+sign
                // on this PUBLIC path. The CA key must not be loaded for an
                // anonymous caller. ServerImpl pre-publishes a CRL at startup and
                // republishes on every revoke, so latest_crl() is populated in
                // steady state; a 503 here means the startup publish failed (an
                // operator/ops condition, not an anonymous-triggerable key load).
                auto latest = ca_store->latest_crl();
                if (!latest || latest->der.empty()) {
                    res.status = 503;
                    res.set_content(error_json_a4(503, "CRL not yet published", make_correlation_id()),
                                    kJson);
                    return;
                }
                const auto& der = latest->der;
                res.set_header("Cache-Control", "no-cache, must-revalidate"); // Hermes L5
                res.set_content(
                    std::string(reinterpret_cast<const char*>(der.data()), der.size()),
                    "application/pkix-crl");
            });

    // ── GET /api/v1/ca/issued ── Security:Read: issued-cert inventory. ────────
    sink.Get("/api/v1/ca/issued",
            [perm_fn, ca_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Security", "Read"))
                    return;
                if (!ca_store || !ca_store->is_open()) {
                    res.status = 503;
                    res.set_content(error_json_a4(503, "CA not available", make_correlation_id()),
                                    kJson);
                    return;
                }
                const int limit = clamp_int(req, "limit", 200, 1, 1000);
                const int offset = clamp_int(req, "offset", 0, 0, 1000000);
                auto records = ca_store->list_issued(limit, offset);
                nlohmann::json items = nlohmann::json::array();
                for (const auto& r : records) {
                    items.push_back({
                        {"serial_hex", r.serial_hex},
                        {"subject", r.subject},
                        {"san", r.san},
                        {"purpose", r.purpose},
                        {"status", cert_status_to_string(r.status)},
                        {"not_after", r.not_after},
                        {"issued_at", r.issued_at},
                        {"revoked_at", r.revoked_at},
                        {"revocation_reason", r.revocation_reason},
                        {"issued_by", r.issued_by},
                    });
                }
                nlohmann::json out = {{"items", std::move(items)},
                                      {"count", records.size()},
                                      {"meta", {{"api_version", "v1"}}}};
                res.set_content(out.dump(), kJson);
            });

    // ── POST /api/v1/ca/revoke ── Security:Delete: revoke a serial. ───────────
    // Body: {"serial_hex": "...", "reason": "..."}. Revocation takes effect
    // server-side immediately (the mTLS accept gate consults ca.db, not the CRL);
    // republishing the CRL propagates it to external consumers.
    sink.Post("/api/v1/ca/revoke", [perm_fn, audit_fn, ca_store, publish_crl_fn](
                                      const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "Security", "Delete"))
            return;
        if (!ca_store || !ca_store->is_open()) {
            res.status = 503;
            res.set_content(error_json_a4(503, "CA not available", make_correlation_id()), kJson);
            return;
        }
        // Hermes M3: bound the body before parsing — a multi-GB POST must not
        // reach nlohmann::json::parse on this privileged endpoint.
        if (req.body.size() > kMaxRevokeBody) {
            res.status = 413;
            res.set_content(error_json_a4(413, "request body too large", make_correlation_id()),
                            kJson);
            return;
        }
        // Hermes INJ-M1: defensively wrap the parse. allow_exceptions=false turns
        // parse errors into a discarded value (caught by !is_object below), but a
        // bad_alloc / impl-specific throw on a privileged endpoint should still
        // yield a clean 400, not propagate.
        nlohmann::json body;
        try {
            body = nlohmann::json::parse(req.body, nullptr, false);
        } catch (...) {
            res.status = 400;
            res.set_content(error_json_a4(400, "invalid JSON body", make_correlation_id()), kJson);
            return;
        }
        if (!body.is_object()) {
            res.status = 400;
            res.set_content(error_json_a4(400, "invalid JSON body", make_correlation_id()), kJson);
            return;
        }
        // Hermes BFLA-M2: reject unknown keys (mass-assignment guard + catches
        // operator typos like "serail_hex" with a clear error instead of a silent
        // empty-serial 400). The handler only acts on serial_hex + reason.
        for (const auto& [k, v] : body.items()) {
            if (k != "serial_hex" && k != "reason") {
                res.status = 400;
                res.set_content(error_json_a4(400, "unknown field in request body",
                                              make_correlation_id(),
                                              "only serial_hex and reason are accepted"),
                                kJson);
                return;
            }
        }
        std::string serial = body.value("serial_hex", "");
        std::string reason = body.value("reason", "").substr(0, 256);
        // gov security LOW: strip CR/LF so an operator-controlled reason can't
        // inject newlines into the audit detail (log-injection defence in depth).
        std::erase_if(reason, [](char c) { return c == '\n' || c == '\r'; });
        // Hermes M4: validate serial_hex (1..64 hex digits) before it reaches the
        // store + audit log; normalise to the canonical uppercase BN_bn2hex form
        // ca.db stores, so a lowercase-input revoke still matches.
        const bool serial_ok =
            !serial.empty() && serial.size() <= 64 &&
            serial.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
        if (!serial_ok) {
            res.status = 400;
            res.set_content(error_json_a4(400, "serial_hex must be 1-64 hex digits",
                                          make_correlation_id(),
                                          "pass the cert's serial_hex from /api/v1/ca/issued"),
                            kJson);
            return;
        }
        for (auto& c : serial)
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (!ca_store->revoke(serial, reason)) {
            // Idempotent: unknown serial or already-revoked. Audit the denied
            // attempt (SOC 2 CC7.2 — a revoke of a non-existent serial is worth a
            // forensic row), then 404.
            audit_fn(req, "ca.cert.revoked", "failure", "AgentCertificate", serial,
                     "serial not found or already revoked");
            res.status = 404;
            res.set_content(
                error_json_a4(404, "serial not found or already revoked", make_correlation_id()),
                kJson);
            return;
        }
        audit_fn(req, "ca.cert.revoked", "success", "AgentCertificate", serial, reason);
        // Republish the CRL so external consumers see the revocation. A failure
        // here does NOT undo the revocation (already enforced server-side) — it is
        // surfaced to the caller so they know the public CRL is momentarily stale.
        bool crl_ok = false;
        if (publish_crl_fn)
            crl_ok = publish_crl_fn().has_value();
        // Hermes M2: audit the republish FAILURE too — a stale public CRL after a
        // revocation is a security-relevant event (SOC 2 CC7.2).
        if (crl_ok)
            audit_fn(req, "ca.crl.published", "success", "Security", serial, "");
        else
            audit_fn(req, "ca.crl.published", "failure", "Security", serial,
                     "CRL build/record failed after revocation; public CRL may be stale");
        nlohmann::json out = {{"revoked", true},
                              {"serial_hex", serial},
                              {"crl_republished", crl_ok},
                              {"meta", {{"api_version", "v1"}}}};
        res.set_content(out.dump(), kJson);
    });
}

} // namespace yuzu::server
