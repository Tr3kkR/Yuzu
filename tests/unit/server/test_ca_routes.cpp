/**
 * test_ca_routes.cpp — HTTP-level coverage for the internal-CA REST surface
 * under /api/v1/ca/ (PKI PR4). Registers CaRoutes against an in-process
 * TestRouteSink (no socket, no acceptor thread — TSan-safe, #438) and
 * dispatches synthesized requests directly into the captured handlers.
 *
 * Coverage: root PEM (200 / 404 no-root), issued inventory (200 shape +
 * 403 perm-denied), revoke (200 + audit + CRL republish, 400 missing serial,
 * 404 already-revoked, 403 perm-denied), CRL (build-on-first then serve-latest),
 * and 503 when the CA store is unavailable.
 */

#include "ca_routes.hpp"
#include "ca_store.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

// Wires CaRoutes against an in-process sink with a real CaStore + fakes for
// perm/audit/CRL. `perm_allow` toggles the permission gate; audit rows are
// captured; `crl_calls` counts publish_crl_fn invocations.
struct Harness {
    yuzu::test::TempDbFile db{std::string_view{"ca-routes-"}};
    std::unique_ptr<CaStore> store{std::make_unique<CaStore>(db.path)};
    test::TestRouteSink sink;
    std::vector<AuditRow> audits;
    bool perm_allow{true};
    bool crl_succeeds{true};   // when false, publish_crl_fn returns nullopt (GAP-2)
    bool audit_succeeds{true}; // when false, AuditFn returns false (#1240 Sec-Audit-Failed)
    int crl_calls{0};
    std::string last_perm_type; // captured (securable, op) of the last perm check
    std::string last_perm_op;

    void wire(bool null_store = false) {
        CaRoutes routes;
        CaRoutes::AuthFn auth = [](const httplib::Request&,
                                   httplib::Response&) -> std::optional<auth::Session> {
            return std::nullopt;
        };
        CaRoutes::PermFn perm = [this](const httplib::Request&, httplib::Response& res,
                                       const std::string& type, const std::string& op) {
            last_perm_type = type;
            last_perm_op = op;
            if (!perm_allow) {
                res.status = 403;
                res.set_content(R"({"error":{"code":403,"message":"denied"}})", "application/json");
                return false;
            }
            return true;
        };
        CaRoutes::AuditFn audit = [this](const httplib::Request&, const std::string& a,
                                         const std::string& r, const std::string& tt,
                                         const std::string& ti, const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds; // #1240: AuditFn now returns bool (observe persist failure)
        };
        CaRoutes::PublishCrlFn crl = [this]() -> std::optional<std::vector<std::uint8_t>> {
            ++crl_calls;
            if (!crl_succeeds)
                return std::nullopt;
            return std::vector<std::uint8_t>{0x30, 0x03, 0x01, 0x02}; // fake DER
        };
        routes.register_routes(sink, auth, perm, audit, null_store ? nullptr : store.get(), crl);
    }
};

CaRoot sample_root() {
    CaRoot r;
    r.cert_pem = "-----BEGIN CERTIFICATE-----\nMIIBfakeRootPEM\n-----END CERTIFICATE-----\n";
    r.key_ref = "/tmp/ca-routes-test-does-not-resolve.key";
    r.algo = "EcP384";
    r.not_before = 1000;
    r.not_after = 9999999999;
    r.fingerprint_sha256 = "AB:CD:EF";
    r.mode = CaMode::Builtin;
    return r;
}

IssuedCertRecord sample_issued(const std::string& serial) {
    IssuedCertRecord r;
    r.serial_hex = serial;
    r.subject = "agent-" + serial;
    r.san = "URI:yuzu://inst/agent/" + serial;
    r.purpose = "agent";
    r.not_after = 9999999999;
    r.cert_pem = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n";
    r.issued_by = "agent:" + serial;
    return r;
}

} // namespace

TEST_CASE("ca_routes: GET /ca/root serves PEM, 404 with no root", "[ca_routes][pki]") {
    Harness h;
    h.wire();
    auto r404 = h.sink.Get("/api/v1/ca/root");
    REQUIRE(r404);
    REQUIRE(r404->status == 404); // no root yet

    REQUIRE(h.store->set_root(sample_root()));
    auto ok = h.sink.Get("/api/v1/ca/root");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    REQUIRE(ok->body.find("BEGIN CERTIFICATE") != std::string::npos);
    REQUIRE(ok->get_header_value("Content-Type") == "application/x-pem-file");
}

TEST_CASE("ca_routes: GET /ca/root is public (no perm gate)", "[ca_routes][pki][security]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.perm_allow = false; // would block a gated route
    h.wire();
    auto ok = h.sink.Get("/api/v1/ca/root");
    REQUIRE(ok);
    REQUIRE(ok->status == 200); // root is public — perm_fn is never consulted
}

TEST_CASE("ca_routes: GET /ca/issued requires Security:Read", "[ca_routes][pki][security]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    REQUIRE(h.store->record_issued(sample_issued("BEEF")));
    h.wire();

    auto ok = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    auto j = json::parse(ok->body);
    REQUIRE(j["count"] == 2);
    REQUIRE(j["items"].size() == 2);
    REQUIRE(j["meta"]["api_version"] == "v1");
    // GAP-1: the inventory must NOT leak the full cert PEM or the enrollment ref
    // (security property — confirm a future refactor can't silently expose them).
    for (const auto& item : j["items"]) {
        REQUIRE_FALSE(item.contains("cert_pem"));
        REQUIRE_FALSE(item.contains("enrollment_request_id"));
    }

    h.perm_allow = false;
    auto denied = h.sink.Get("/api/v1/ca/issued");
    REQUIRE(denied);
    REQUIRE(denied->status == 403);
}

TEST_CASE("ca_routes: POST /ca/revoke flow", "[ca_routes][pki][security]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();

    // Missing serial → 400.
    auto bad = h.sink.Post("/api/v1/ca/revoke", R"({})");
    REQUIRE(bad);
    REQUIRE(bad->status == 400);

    // Valid revoke → 200, audited, CRL republished.
    auto ok = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"DEAD","reason":"compromised"})");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    auto j = json::parse(ok->body);
    REQUIRE(j["revoked"] == true);
    REQUIRE(j["crl_republished"] == true);
    REQUIRE(h.crl_calls == 1);
    REQUIRE(h.store->is_revoked("DEAD"));

    bool saw_revoke = false, saw_crl = false;
    for (const auto& a : h.audits) {
        if (a.action == "ca.cert.revoked" && a.result == "success" && a.target_id == "DEAD")
            saw_revoke = true;
        if (a.action == "ca.crl.published" && a.result == "success")
            saw_crl = true;
    }
    REQUIRE(saw_revoke);
    REQUIRE(saw_crl);

    // Re-revoke an already-revoked serial → 404 + a "denied" audit row (#1240:
    // reject-without-state-change uses "denied" like every destructive sibling;
    // "failure" is reserved for an authorized-but-errored op). This is also the
    // idempotency case — a retry of a successful revoke must not log a false error.
    auto again = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"DEAD"})");
    REQUIRE(again);
    REQUIRE(again->status == 404);
    bool saw_denied = false;
    for (const auto& a : h.audits)
        if (a.action == "ca.cert.revoked" && a.result == "denied")
            saw_denied = true;
    REQUIRE(saw_denied);

    // Perm denied → 403, no revoke attempted, and NO audit row emitted by the
    // handler (#1240: the perm gate runs before any audit_fn call; the denied
    // audit is the perm layer's responsibility, not the route's — asserting zero
    // new rows here proves the route doesn't double-audit or leak a row on 403).
    const std::size_t audits_before = h.audits.size();
    h.perm_allow = false;
    auto denied = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"BEEF"})");
    REQUIRE(denied);
    REQUIRE(denied->status == 403);
    REQUIRE(h.audits.size() == audits_before); // handler emitted no audit row on 403
}

TEST_CASE("ca_routes: GET /ca/crl serves latest-or-503, never builds on the public path",
          "[ca_routes][pki][security]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();

    // No published CRL yet → 503 (Hermes M1: the public path must NOT load the CA
    // key to build+sign — that is the server's startup/republish job).
    auto none = h.sink.Get("/api/v1/ca/crl");
    REQUIRE(none);
    REQUIRE(none->status == 503);
    REQUIRE(h.crl_calls == 0); // publish_crl_fn never invoked from the public GET

    // Record a CRL version (as the startup pre-publish / a revoke would) → served.
    CrlVersionRecord rec;
    rec.version = 5;
    rec.der = {0x30, 0x01, 0x00};
    rec.this_update = 1;
    rec.next_update = 2;
    REQUIRE(h.store->record_crl(rec));
    auto served = h.sink.Get("/api/v1/ca/crl");
    REQUIRE(served);
    REQUIRE(served->status == 200);
    REQUIRE(served->get_header_value("Content-Type") == "application/pkix-crl");
    REQUIRE(served->get_header_value("Cache-Control").find("no-cache") != std::string::npos);
    REQUIRE(h.crl_calls == 0); // still served from latest_crl, no build
    REQUIRE(served->body.size() == 3);
}

TEST_CASE("ca_routes: /ca/root sets download + cache headers", "[ca_routes][pki]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    h.wire();
    auto ok = h.sink.Get("/api/v1/ca/root");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    REQUIRE(ok->get_header_value("Content-Disposition").find("attachment") != std::string::npos);
    REQUIRE(ok->get_header_value("Cache-Control").find("max-age") != std::string::npos);
}

TEST_CASE("ca_routes: revoke validates serial + bounds the body", "[ca_routes][pki][security]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();

    // Non-hex serial → 400 (Hermes M4).
    auto nonhex = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"zzzz"})");
    REQUIRE(nonhex);
    REQUIRE(nonhex->status == 400);

    // Unknown field → 400 (Hermes BFLA-M2 mass-assignment guard); the revoke must
    // NOT proceed.
    auto extra = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"DEAD","is_admin":true})");
    REQUIRE(extra);
    REQUIRE(extra->status == 400);
    REQUIRE_FALSE(h.store->is_revoked("DEAD"));

    // Over-length serial (>64) → 400.
    auto long_serial = std::string(65, 'A');
    auto toolong = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":")" + long_serial + R"("})");
    REQUIRE(toolong);
    REQUIRE(toolong->status == 400);

    // Oversized body → 413 (Hermes M3), before JSON parse.
    std::string big = R"({"serial_hex":"DEAD","reason":")" + std::string(70000, 'x') + R"("})";
    auto big_res = h.sink.Post("/api/v1/ca/revoke", big);
    REQUIRE(big_res);
    REQUIRE(big_res->status == 413);

    // Lowercase hex is normalized to the canonical uppercase ca.db form → matches.
    auto lower = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"dead","reason":"lc"})");
    REQUIRE(lower);
    REQUIRE(lower->status == 200);
    REQUIRE(h.store->is_revoked("DEAD"));
}

TEST_CASE("ca_routes: revoke succeeds but CRL republish fails is audited", "[ca_routes][pki]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.crl_succeeds = false; // GAP-2: publish_crl_fn returns nullopt
    h.wire();

    auto ok = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"DEAD"})");
    REQUIRE(ok);
    REQUIRE(ok->status == 200); // revocation still stands
    auto j = json::parse(ok->body);
    REQUIRE(j["revoked"] == true);
    REQUIRE(j["crl_republished"] == false);
    REQUIRE(h.store->is_revoked("DEAD")); // enforced server-side regardless

    bool revoke_ok = false, crl_fail = false;
    for (const auto& a : h.audits) {
        if (a.action == "ca.cert.revoked" && a.result == "success")
            revoke_ok = true;
        if (a.action == "ca.crl.published" && a.result == "failure")
            crl_fail = true;
    }
    REQUIRE(revoke_ok);
    REQUIRE(crl_fail); // the republish FAILURE is on the evidence chain
}

TEST_CASE("ca_routes: a dropped audit row on a successful revoke sets Sec-Audit-Failed (#1240 M2)",
          "[ca_routes][pki][security]") {
    // The AuditFn is bool-returning; a privileged revoke whose audit row fails to
    // persist must signal the evidence-chain gap to the operator (Sec-Audit-Failed)
    // while the revoke itself still stands. Without a test, a regression in the
    // header wiring would silently break that signal.
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.audit_succeeds = false; // simulate an audit-store write failure
    h.wire();

    auto ok = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"DEAD"})");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);                       // the revoke still succeeded
    REQUIRE(json::parse(ok->body)["revoked"] == true);
    REQUIRE(h.store->is_revoked("DEAD"));             // enforced regardless
    REQUIRE(ok->get_header_value("Sec-Audit-Failed") == "true"); // gap surfaced
}

TEST_CASE("ca_routes: /ca/issued pagination params are accepted + clamped", "[ca_routes][pki]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("AA01")));
    h.wire();
    // limit=0 (→clamped to 1) and an absurd limit (→clamped) both 200, no error.
    for (const char* q : {"/api/v1/ca/issued?limit=0", "/api/v1/ca/issued?limit=999999",
                          "/api/v1/ca/issued?offset=-5", "/api/v1/ca/issued?limit=abc"}) {
        auto r = h.sink.Get(q);
        REQUIRE(r);
        REQUIRE(r->status == 200);
    }
}

TEST_CASE("ca_routes: dashboard fragment renders, gated, and HTML-escapes (PR4b)",
          "[ca_routes][pki][security]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    // A cert whose subject carries an XSS payload — must be escaped in the table.
    IssuedCertRecord evil = sample_issued("CAFE");
    evil.subject = "<script>alert(1)</script>";
    REQUIRE(h.store->record_issued(evil));
    h.wire();

    auto frag = h.sink.Get("/fragments/settings/ca");
    REQUIRE(frag);
    REQUIRE(frag->status == 200);
    REQUIRE(frag->get_header_value("Content-Type").find("text/html") != std::string::npos);
    // Root info + download links present.
    REQUIRE(frag->body.find("/api/v1/ca/root") != std::string::npos);
    REQUIRE(frag->body.find("/api/v1/ca/crl") != std::string::npos);
    REQUIRE(frag->body.find(sample_root().fingerprint_sha256) != std::string::npos);
    // XSS payload is escaped, not raw.
    REQUIRE(frag->body.find("<script>alert(1)</script>") == std::string::npos);
    REQUIRE(frag->body.find("&lt;script&gt;") != std::string::npos);
    // A revoke control for the active cert is present.
    REQUIRE(frag->body.find("/api/settings/ca/revoke") != std::string::npos);

    // Gated on Security:Read.
    h.perm_allow = false;
    auto denied = h.sink.Get("/fragments/settings/ca");
    REQUIRE(denied);
    REQUIRE(denied->status == 403);
}

TEST_CASE("ca_routes: dashboard revoke wrapper revokes + re-renders (PR4b)",
          "[ca_routes][pki][security]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();

    // Same-origin headers so the (now mandatory) CSRF gate passes; the handler
    // reads serial/reason from params (HTMX hx-vals → form body in production; the
    // TestRouteSink parses the query string into req.params, and the handler reads
    // get_param_value either way). → 200 HTML.
    const std::unordered_map<std::string, std::string> same_origin = {
        {"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}};
    auto ok = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=dead&reason=panel", "",
                              "application/x-www-form-urlencoded", same_origin);
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    REQUIRE(ok->get_header_value("Content-Type").find("text/html") != std::string::npos);
    REQUIRE(h.store->is_revoked("DEAD")); // lowercase input normalised + matched
    REQUIRE(ok->body.find("Revoked") != std::string::npos); // re-rendered with the new status
    REQUIRE(h.crl_calls == 1);                              // republished via revoke_core

    // Invalid serial → 400 HTML, full panel re-rendered (not a bare span).
    auto bad = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=zz", "",
                               "application/x-www-form-urlencoded", same_origin);
    REQUIRE(bad);
    REQUIRE(bad->status == 400);
    REQUIRE(bad->body.find("<table") != std::string::npos); // inline error + full fragment

    // Gated on Security:Delete (CSRF passes via same-origin headers, then perm denies).
    h.perm_allow = false;
    auto denied = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=DEAD", "",
                                  "application/x-www-form-urlencoded", same_origin);
    REQUIRE(denied);
    REQUIRE(denied->status == 403);
}

TEST_CASE("ca_routes: /ca/issued reports has_more + next_offset across pages",
          "[ca_routes][pki]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    // Three distinct issued certs; page through them two at a time.
    REQUIRE(h.store->record_issued(sample_issued("AA01")));
    REQUIRE(h.store->record_issued(sample_issued("AA02")));
    REQUIRE(h.store->record_issued(sample_issued("AA03")));
    h.wire();

    // Page 1: limit=2 of 3 → has_more=true, next_offset=2, exactly 2 items
    // returned (the probe row must be trimmed, not leaked into the page).
    auto p1 = h.sink.Get("/api/v1/ca/issued?limit=2");
    REQUIRE(p1);
    REQUIRE(p1->status == 200);
    auto j1 = json::parse(p1->body);
    REQUIRE(j1["items"].size() == 2);
    REQUIRE(j1["count"] == 2);
    REQUIRE(j1["meta"]["has_more"] == true);
    REQUIRE(j1["meta"]["next_offset"] == 2);
    REQUIRE(j1["meta"]["limit"] == 2);
    REQUIRE(j1["meta"]["offset"] == 0);

    // Page 2: offset=2 → the last record, has_more=false, no next_offset.
    auto p2 = h.sink.Get("/api/v1/ca/issued?limit=2&offset=2");
    REQUIRE(p2);
    REQUIRE(p2->status == 200);
    auto j2 = json::parse(p2->body);
    REQUIRE(j2["items"].size() == 1);
    REQUIRE(j2["meta"]["has_more"] == false);
    REQUIRE(j2["meta"].contains("next_offset") == false);

    // Exactly at the boundary: limit==total → has_more=false (the probe found
    // no extra row), no spurious extra page.
    auto exact = h.sink.Get("/api/v1/ca/issued?limit=3");
    REQUIRE(exact);
    auto je = json::parse(exact->body);
    REQUIRE(je["items"].size() == 3);
    REQUIRE(je["meta"]["has_more"] == false);
}

TEST_CASE("ca_routes: 503 when CA store unavailable", "[ca_routes][pki]") {
    Harness h;
    h.wire(/*null_store=*/true);
    for (const char* path : {"/api/v1/ca/root", "/api/v1/ca/crl", "/api/v1/ca/issued"}) {
        auto r = h.sink.Get(path);
        REQUIRE(r);
        REQUIRE(r->status == 503);
    }
    auto rev = h.sink.Post("/api/v1/ca/revoke", R"({"serial_hex":"DEAD"})");
    REQUIRE(rev);
    REQUIRE(rev->status == 503);
}

// ── PR4b dashboard panel (#1241) ────────────────────────────────────────────

TEST_CASE("ca_routes: dashboard revoke refuses a cross-origin POST (H-1 CSRF)",
          "[ca_routes][pki][security]") {
    // H-1: the dashboard revoke is cookie-authed; SameSite=Lax does not block a
    // top-level cross-site form POST, so a forged revoke (= fleet-lockout DoS)
    // must be refused by the Origin/Referer gate + audited csrf.denied, and the
    // cert must NOT be revoked.
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();

    auto res = h.sink.dispatch(
        "POST", "/api/settings/ca/revoke?serial_hex=DEAD", "", "application/x-www-form-urlencoded",
        {{"Host", "yuzu.example"}, {"Origin", "https://attacker.example"}});
    REQUIRE(res);
    REQUIRE(res->status == 403);
    REQUIRE_FALSE(h.store->is_revoked("DEAD")); // not revoked — gate fired first
    bool saw_csrf = false;
    for (const auto& a : h.audits)
        if (a.action == "csrf.denied")
            saw_csrf = true;
    REQUIRE(saw_csrf);
    // The CSRF gate runs BEFORE perm_fn (no perm/role oracle to a cross-site
    // probe), so perm is never consulted on a refused cross-origin request.
    REQUIRE(h.last_perm_type.empty());
}

TEST_CASE("ca_routes: dashboard revoke with NO Origin/Referer is refused (destructive endpoint)",
          "[ca_routes][pki][security]") {
    // Hermes PR4b M: a browser HTMX POST always carries Origin (or Referer), so a
    // request with NEITHER on this DESTRUCTIVE cookie endpoint is treated as
    // cross-site — closing the both-empty gap a header-stripping proxy could ride.
    // (Token automation must use the REST endpoint.)
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("BEEF")));
    h.wire();
    auto res = h.sink.dispatch("POST", "/api/settings/ca/revoke?serial_hex=BEEF", "",
                               "application/x-www-form-urlencoded", {{"Host", "yuzu.example"}});
    REQUIRE(res);
    REQUIRE(res->status == 403);
    REQUIRE_FALSE(h.store->is_revoked("BEEF"));
}

TEST_CASE("ca_routes: dashboard revoke proceeds for a same-origin POST + re-renders the panel",
          "[ca_routes][pki][security]") {
    Harness h;
    REQUIRE(h.store->set_root(sample_root()));
    REQUIRE(h.store->record_issued(sample_issued("DEAD")));
    h.wire();

    auto res = h.sink.dispatch(
        "POST", "/api/settings/ca/revoke?serial_hex=DEAD&reason=decommissioned", "",
        "application/x-www-form-urlencoded",
        {{"Host", "yuzu.example"}, {"Origin", "https://yuzu.example"}});
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(h.store->is_revoked("DEAD"));                          // revoked
    REQUIRE(res->body.find("Revoked") != std::string::npos);      // panel re-rendered
    REQUIRE(res->body.find("<table") != std::string::npos);       // full fragment, not a bare span
    // The revoke route gates on Security:Delete (not Read) — asserted on the
    // path that actually reaches perm_fn (same-origin).
    REQUIRE(h.last_perm_type == "Security");
    REQUIRE(h.last_perm_op == "Delete");
    // The reason was recorded (UP-7).
    auto rec = h.store->get_issued("DEAD");
    REQUIRE(rec);
    REQUIRE(rec->revocation_reason == "decommissioned");
}

TEST_CASE("ca_routes: dashboard fragment renders empty-CA + no-root states without crashing",
          "[ca_routes][pki]") {
    {
        Harness h; // no root set
        h.wire();
        auto res = h.sink.Get("/fragments/settings/ca");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        REQUIRE(res->body.find("No internal CA") != std::string::npos);
    }
    {
        Harness h;
        h.wire(/*null_store=*/true); // CA store unavailable
        auto res = h.sink.Get("/fragments/settings/ca");
        REQUIRE(res);
        REQUIRE(res->body.find("unavailable") != std::string::npos);
    }
}
