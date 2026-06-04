#include "ca_routes.hpp"

#include "rest_a4_envelope.hpp"
#include "web_utils.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cctype>
#include <cstddef>
#include <ctime>
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

std::string fmt_epoch(int64_t epoch) {
    if (epoch == 0)
        return "—";
    auto tt = static_cast<std::time_t>(epoch);
    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &tt);
#else
    gmtime_r(&tt, &tm_buf);
#endif
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_buf);
    return std::string(buf);
}

/// Validate + normalise a serial to the canonical uppercase hex `ca.db` stores.
/// Returns empty if it is not 1–64 hex digits. Shared by the REST + dashboard
/// revoke paths so both reject the same inputs and match the same stored serial.
std::string normalize_serial(std::string s) {
    if (s.empty() || s.size() > 64 ||
        s.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
        return {};
    for (auto& c : s)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

/// Server-rendered HTMX fragment for the Settings → Internal CA panel (PKI PR4b).
/// Dark-theme product UI (NOT frontend-design). All agent-controlled fields
/// (subject, SAN) go through html_escape. Revoke buttons post to the settings
/// wrapper; downloads link to the public REST endpoints.
std::string render_ca_fragment(CaStore* ca_store) {
    if (!ca_store || !ca_store->is_open())
        return "<span style=\"color:#484f58\">Certificate authority unavailable.</span>";
    auto root = ca_store->get_root();
    std::string html;
    if (!root) {
        html += "<p style=\"color:#484f58\">No internal CA on this install (operator-supplied "
                "certificates, or TLS disabled).</p>";
        return html;
    }

    html += "<div style=\"margin-bottom:0.75rem;font-size:0.8rem\">"
            "<div><strong>Algorithm:</strong> " +
            html_escape(root->algo) + "</div>"
            "<div><strong>SHA-256:</strong> <code style=\"font-size:0.7rem\">" +
            html_escape(root->fingerprint_sha256) + "</code></div>"
            "<div><strong>Expires:</strong> " + fmt_epoch(root->not_after) + " UTC</div>"
            "</div>"
            "<div style=\"margin-bottom:1rem;display:flex;gap:0.5rem;flex-wrap:wrap\">"
            "<a class=\"btn\" style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
            "href=\"/api/v1/ca/root\">Download CA certificate</a>"
            "<a class=\"btn\" style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
            "href=\"/api/v1/ca/crl\">Download CRL</a>"
            "</div>";

    auto issued = ca_store->list_issued(500, 0);
    html += "<table class=\"user-table\">"
            "<thead><tr><th>Serial</th><th>Subject</th><th>Purpose</th><th>Expires</th>"
            "<th>Status</th><th></th></tr></thead><tbody>";
    if (issued.empty()) {
        html += "<tr><td colspan=\"6\" style=\"color:#484f58\">No certificates issued yet</td></tr>";
    } else {
        for (const auto& c : issued) {
            const bool revoked = c.status == CertStatus::Revoked;
            const std::string short_serial =
                c.serial_hex.size() > 16 ? c.serial_hex.substr(0, 16) + "…" : c.serial_hex;
            html += "<tr><td><code style=\"font-size:0.7rem\" title=\"" +
                    html_escape(c.serial_hex) + "\">" + html_escape(short_serial) +
                    "</code></td>"
                    "<td>" + html_escape(c.subject) + "</td>"
                    "<td>" + html_escape(c.purpose) + "</td>"
                    "<td style=\"font-size:0.75rem\">" + fmt_epoch(c.not_after) +
                    "</td>"
                    "<td><span class=\"role-badge " +
                    (revoked ? "role-user\">Revoked" : "role-admin\">Active") + "</span></td><td>";
            if (!revoked) {
                // Carry the serial in a hidden input rather than a JSON hx-vals
                // attribute: simpler, and it avoids JSON-inside-an-HTML-attribute
                // escaping entirely. html_escape covers &, <, >, " AND ' (→ &#39;,
                // see web_utils.hpp), so the double-quoted value="" is safe for any
                // serial (and a single-quoted hx-vals would have been too) — the
                // form is just the clearer, codebase-standard pattern. The serial
                // is hex-only in practice; this renders whatever ca.db holds safely.
                html += "<form hx-post=\"/api/settings/ca/revoke\" hx-target=\"#ca-section\" "
                        "hx-swap=\"innerHTML\" style=\"display:inline\" "
                        "hx-confirm=\"Revoke certificate for &quot;" +
                        html_escape(c.subject) +
                        "&quot;? The agent is refused on its next connection.\">"
                        "<input type=\"hidden\" name=\"serial_hex\" value=\"" +
                        html_escape(c.serial_hex) +
                        "\">"
                        "<button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "type=\"submit\">Revoke</button></form>";
            }
            html += "</td></tr>";
        }
    }
    html += "</tbody></table>"
            "<p style=\"font-size:0.72rem;color:var(--mds-color-theme-text-tertiary);"
            "margin-top:0.75rem\">To replace the default certificates with operator- or "
            "HSM-issued material, use <strong>TLS / mTLS Configuration</strong> above. "
            "Revocation takes effect immediately server-side; the public CRL is republished "
            "automatically.</p>";
    return html;
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
    spdlog::info("CA routes: registering /api/v1/ca/* + Settings CA panel");

    // Shared revoke core (REST + dashboard wrapper) over an ALREADY-normalised
    // serial: revoke → audit → republish CRL → audit. Returns -1 unknown/already-
    // revoked, 0 revoked-but-CRL-stale, 1 revoked+CRL-republished. Copied by value
    // into the handler lambdas so it outlives this stack frame.
    auto revoke_core = [ca_store, audit_fn, publish_crl_fn](
                           const httplib::Request& req, const std::string& serial,
                           const std::string& reason) -> int {
        if (!ca_store->revoke(serial, reason)) {
            audit_fn(req, "ca.cert.revoked", "failure", "AgentCertificate", serial,
                     "serial not found or already revoked");
            return -1;
        }
        audit_fn(req, "ca.cert.revoked", "success", "AgentCertificate", serial, reason);
        const bool crl_ok = publish_crl_fn && publish_crl_fn().has_value();
        if (crl_ok)
            audit_fn(req, "ca.crl.published", "success", "Security", serial, "");
        else
            audit_fn(req, "ca.crl.published", "failure", "Security", serial,
                     "CRL build/record failed after revocation; public CRL may be stale");
        return crl_ok ? 1 : 0;
    };

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
    sink.Post("/api/v1/ca/revoke", [perm_fn, ca_store, revoke_core](
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
        std::string reason = body.value("reason", "").substr(0, 256);
        // gov security LOW: strip CR/LF so an operator-controlled reason can't
        // inject newlines into the audit detail (log-injection defence in depth).
        std::erase_if(reason, [](char c) { return c == '\n' || c == '\r'; });
        // Hermes M4: validate + normalise serial_hex (1..64 hex, uppercase) so a
        // lowercase-input revoke still matches the canonical ca.db form.
        const std::string serial = normalize_serial(body.value("serial_hex", ""));
        if (serial.empty()) {
            res.status = 400;
            res.set_content(error_json_a4(400, "serial_hex must be 1-64 hex digits",
                                          make_correlation_id(),
                                          "pass the cert's serial_hex from /api/v1/ca/issued"),
                            kJson);
            return;
        }
        const int rc = revoke_core(req, serial, reason);
        if (rc < 0) {
            res.status = 404;
            res.set_content(
                error_json_a4(404, "serial not found or already revoked", make_correlation_id()),
                kJson);
            return;
        }
        nlohmann::json out = {{"revoked", true},
                              {"serial_hex", serial},
                              {"crl_republished", rc == 1},
                              {"meta", {{"api_version", "v1"}}}};
        res.set_content(out.dump(), kJson);
    });

    // ── GET /fragments/settings/ca ── Settings → Internal CA panel (PR4b). ────
    // Server-rendered HTMX fragment (admin reaches /settings; the fragment itself
    // gates on Security:Read for RBAC parity with GET /ca/issued). Dark-theme
    // product UI; all agent-controlled fields are html_escaped in render_ca_fragment.
    sink.Get("/fragments/settings/ca",
             [perm_fn, ca_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "Security", "Read"))
                     return;
                 res.set_content(render_ca_fragment(ca_store), "text/html; charset=utf-8");
             });

    // ── POST /api/settings/ca/revoke ── dashboard revoke wrapper (PR4b). ──────
    // Form-encoded (HTMX hx-vals); Security:Delete. Re-renders the panel fragment
    // so the HTMX swap shows the updated inventory. Shares revoke_core with the
    // JSON REST endpoint (same validation, audit, CRL republish).
    sink.Post("/api/settings/ca/revoke",
              [perm_fn, ca_store, revoke_core](const httplib::Request& req, httplib::Response& res) {
                  if (!perm_fn(req, res, "Security", "Delete"))
                      return;
                  if (!ca_store || !ca_store->is_open()) {
                      res.status = 503;
                      res.set_content("<span style=\"color:#f85149\">CA unavailable.</span>",
                                      "text/html; charset=utf-8");
                      return;
                  }
                  std::string reason = req.get_param_value("reason").substr(0, 256);
                  std::erase_if(reason, [](char c) { return c == '\n' || c == '\r'; });
                  const std::string serial = normalize_serial(req.get_param_value("serial_hex"));
                  if (serial.empty()) {
                      res.status = 400;
                      res.set_content("<span style=\"color:#f85149\">Invalid serial.</span>",
                                      "text/html; charset=utf-8");
                      return;
                  }
                  (void)revoke_core(req, serial, reason); // -1 (already gone) is fine — re-render
                  res.set_content(render_ca_fragment(ca_store), "text/html; charset=utf-8");
              });
}

} // namespace yuzu::server
