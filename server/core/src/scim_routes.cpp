#include "scim_routes.hpp"

#include "audit_store.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/scim_json.hpp>
#include <yuzu/server/server.hpp> // Config — scim_boot_guard_ok

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

// ── Boot guard (S-BOOTGUARD-TEST) ───────────────────────────────────────────

// M1 (2026-07-08 review): floor on the operator-supplied bearer token.
// ScimStore stores it as unsalted single-round SHA-256 (S-BEARER-HASH) —
// verify-only, but with no per-attempt slowdown, so a short/weak token is
// brute-forceable against a leaked hash far faster than a properly-sized
// credential. 24 chars is generous headroom over a 128-bit CSPRNG token
// hex-encoded (32 chars) while still accepting a hand-typed high-entropy
// passphrase.
constexpr std::size_t kMinScimTokenLength = 24;

bool scim_boot_guard_ok(const Config& cfg, std::string& err) {
    if (!cfg.scim_enable)
        return true;
    if (cfg.scim_token.empty()) {
        err = "--scim-enable requires --scim-token (or YUZU_SCIM_TOKEN) — refusing "
              "to start an unauthenticated provisioning surface.";
        return false;
    }
    if (cfg.scim_token.size() < kMinScimTokenLength) {
        err = "--scim-token must be at least " + std::to_string(kMinScimTokenLength) +
              " characters (it is stored as an unsalted SHA-256 hash and is the sole "
              "credential gating an account-provisioning surface) — refusing to start "
              "with a short/low-entropy token.";
        return false;
    }
    if (!cfg.https_enabled) {
        err = "--scim-enable requires HTTPS (the bearer token would otherwise cross "
              "the wire in plaintext) — refusing to start with --no-https set. Enable "
              "HTTPS or disable --scim-enable.";
        return false;
    }
    return true;
}

namespace {

using json = nlohmann::json;

constexpr const char* kScimJson = "application/scim+json";
// Bound POST/PUT/PATCH bodies before parsing — a real SCIM User payload
// (even with IdP-sent fields Yuzu ignores: name, emails, groups, ...) is a
// few KB; 64 KiB is generous headroom while refusing a multi-MB POST on this
// provisioning surface.
constexpr std::size_t kMaxBodyBytes = 64 * 1024;

void send_scim_error(httplib::Response& res, int status, std::string_view detail,
                     std::string_view scim_type = "") {
    res.status = status;
    res.set_content(scim::error(status, detail, scim_type).dump(), kScimJson);
}

void send_scim_error(httplib::Response& res, const scim::ScimError& e) {
    res.status = e.status;
    res.set_content(scim::error(e).dump(), kScimJson);
}

/// S-BOUND-INTPARAM (sec MEDIUM-2): parse a SCIM list query int param
/// (`startIndex`/`count`) with a shape check on the raw string BEFORE ever
/// handing it to `std::stoi` — an empty value, non-numeric garbage, or an
/// absurdly long digit string must fail cleanly with a SCIM 400
/// `invalidValue`, never an unhandled `std::invalid_argument`/
/// `std::out_of_range` escaping to an unhandled-exception 500. `raw` is
/// rejected if empty, longer than 10 characters (a legitimate startIndex/
/// count never needs more digits than `INT_MAX`), or not all-digits with an
/// optional leading `-`. `std::stoi` is still wrapped in try/catch as
/// belt-and-suspenders. On failure, sends the 400 response and returns
/// `std::nullopt`; the caller is responsible for `record_request(...)`.
std::optional<int> parse_scim_int_param(httplib::Response& res, std::string_view raw,
                                        std::string_view param_name) {
    bool shape_ok = !raw.empty() && raw.size() <= 10;
    if (shape_ok) {
        std::size_t i = (raw.front() == '-') ? 1 : 0;
        shape_ok = i < raw.size();
        for (; shape_ok && i < raw.size(); ++i)
            shape_ok = std::isdigit(static_cast<unsigned char>(raw[i])) != 0;
    }
    if (shape_ok) {
        try {
            return std::stoi(std::string(raw));
        } catch (const std::exception&) {
            shape_ok = false;
        }
    }
    send_scim_error(res, 400, std::string(param_name) + " must be an integer", "invalidValue");
    return std::nullopt;
}

/// Fixed audit principal — there is no session/human operator on this
/// bearer-only surface (see scim_routes.hpp header doc).
constexpr const char* kScimPrincipal = "scim-service";

// ── Metrics (M-METRICS) ─────────────────────────────────────────────────────

/// Bucket an HTTP status into Prometheus's conventional 2xx/4xx/5xx label so
/// `yuzu_scim_requests_total` stays low-cardinality regardless of the exact
/// status code.
std::string_view status_bucket(int status) {
    if (status >= 200 && status < 300)
        return "2xx";
    if (status >= 400 && status < 500)
        return "4xx";
    if (status >= 500)
        return "5xx";
    return "other";
}

/// Record one `/scim/v2/Users` request outcome. `op` is one of
/// create/get/list/replace/patch/delete. No-op when no MetricsRegistry is
/// wired (AuthManager::metrics_registry() is null in test/CLI contexts).
void record_request(auth::AuthManager* auth_mgr, const char* op, int status) {
    if (!auth_mgr)
        return;
    auto* m = auth_mgr->metrics_registry();
    if (!m)
        return;
    m->counter("yuzu_scim_requests_total",
               {{"op", op}, {"status", std::string(status_bucket(status))}})
        .increment();
}

void bump_auth_failure(auth::AuthManager* auth_mgr) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_auth_failures_total").increment();
}

void bump_audit_write_failure(auth::AuthManager* auth_mgr, const std::string& action) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_audit_write_failures_total", {{"action", action}}).increment();
}

void bump_provenance_denied(auth::AuthManager* auth_mgr) {
    if (!auth_mgr)
        return;
    if (auto* m = auth_mgr->metrics_registry())
        m->counter("yuzu_scim_provenance_denied_total").increment();
}

// ── Audit ────────────────────────────────────────────────────────────────

/// Emit a SCIM audit row. AuditStore::log is [[nodiscard]] bool; per the
/// evidence-integrity contract (audit_store.hpp) EVERY caller on this
/// surface — including the three termination actions (deactivated/deleted/
/// reactivated) — "set-and-proceed" rather than fail the IdP's request over
/// an audit-store hiccup: the mutation already committed, and a fail-closed
/// 500 here does not help, because the IdP's retry observes post-state
/// (e.g. the account is already inactive) and takes the non-termination
/// branch on the next request — it never re-attempts the lost audit write,
/// so failing closed only costs the caller a spurious 500 without
/// recovering the evidence row. CC6.8 evidence integrity is instead
/// enforced by an alert on `yuzu_scim_audit_write_failures_total`, which
/// every failure (including `audit_store == nullptr`, an equally real
/// evidence gap) bumps regardless of the caller's response.
bool audit(auth::AuthManager* auth_mgr, AuditStore* audit_store, const httplib::Request& req,
          const std::string& action, const std::string& result, const std::string& target_id,
          const std::string& detail = {}) {
    if (!audit_store) {
        bump_audit_write_failure(auth_mgr, action);
        return false;
    }
    AuditEvent ev;
    ev.principal = kScimPrincipal;
    ev.principal_role = kScimPrincipal; // S-PRINCIPAL-ROLE — every other machine principal sets one
    ev.action = action;
    ev.target_type = "User";
    ev.target_id = target_id;
    ev.detail = detail;
    ev.result = result;
    ev.source_ip = req.remote_addr;
    ev.user_agent = req.get_header_value("User-Agent");
    bool ok = audit_store->log(ev);
    if (!ok) {
        spdlog::error("ScimRoutes: audit write failed action='{}' target_id='{}' result='{}'",
                     action, target_id, result);
        bump_audit_write_failure(auth_mgr, action);
    }
    return ok;
}

/// Build the `/scim/v2/Users` collection URL for this request so
/// `scim::user_to_json`'s `meta.location` / the `Location` header point at a
/// resolvable absolute URL. `--scim-enable` refuses to start without HTTPS
/// (see main.cpp), so "https" is the safe assumed scheme when no reverse
/// proxy sets X-Forwarded-Proto.
std::string location_base(const httplib::Request& req) {
    std::string scheme = req.get_header_value("X-Forwarded-Proto");
    if (scheme.empty())
        scheme = "https";
    std::string host = req.get_header_value("Host");
    return scheme + "://" + host + "/scim/v2/Users";
}

/// Bearer gate shared by every /scim/v2/* route. Reads ONLY the
/// `Authorization: Bearer <token>` header (no cookie/CSRF — there is no
/// session on this surface) and validates it against ScimStore's hashed
/// token(s). On failure, sends 401 + WWW-Authenticate + a SCIM error body,
/// audits `scim.auth.denied` + bumps `yuzu_scim_auth_failures_total`
/// (M-BEARER-AUDIT — a rejected bearer against a surface that can
/// provision/deprovision operator accounts is a credential-guess/replay
/// signal), and returns false so the caller can bail out of the handler.
bool require_bearer(ScimStore* scim_store, auth::AuthManager* auth_mgr, AuditStore* audit_store,
                    const httplib::Request& req, httplib::Response& res) {
    constexpr std::string_view kPrefix = "Bearer ";
    std::string token;
    if (auto h = req.get_header_value("Authorization");
        h.size() > kPrefix.size() && h.compare(0, kPrefix.size(), kPrefix) == 0) {
        token = h.substr(kPrefix.size());
    }
    if (!scim_store || !scim_store->is_open() || token.empty() ||
        !scim_store->validate_token(token)) {
        res.status = 401;
        res.set_header("WWW-Authenticate", "Bearer");
        res.set_content(scim::error(401, "invalid or missing bearer token").dump(), kScimJson);
        audit(auth_mgr, audit_store, req, "scim.auth.denied", "denied", "");
        bump_auth_failure(auth_mgr);
        return false;
    }
    return true;
}

/// LOAD-BEARING SECURITY INVARIANT — the provenance guard. SCIM must only
/// ever mutate accounts IT provisioned. `ScimStore::get_by_scim_id` already
/// gives defense against a locally-created admin (which has no scim_resource
/// row at all, so the caller 404s before this is even reached) — this is a
/// SECOND, independent check straight against the auth substrate: even if a
/// scim_resource row somehow existed for a non-SCIM account (e.g. a future
/// bug, or an operator hand-editing scim_resources), we refuse to touch the
/// underlying auth account unless `provisioning_source == "scim"` RIGHT NOW.
/// Returns true iff the mutation may proceed. On refusal, sends 404 (NEVER
/// 403 — a 403 would confirm to the IdP that a local account by this name
/// exists) and audits `scim.user.provenance_denied`.
bool provenance_ok(auth::AuthManager* auth_mgr, AuditStore* audit_store,
                   const httplib::Request& req, const std::string& username,
                   const std::string& scim_id, httplib::Response& res) {
    AuthDB* db = auth_mgr ? auth_mgr->auth_db_ptr() : nullptr;
    if (!db) {
        // No persistent AuthDB configured — SCIM cannot durably record/verify
        // provenance, so refuse rather than risk mutating an account we can't
        // prove we provisioned.
        spdlog::error("ScimRoutes: provenance check unavailable (no AuthDB) — refusing "
                     "mutation of '{}'",
                     username);
        send_scim_error(res, 404, "resource not found");
        audit(auth_mgr, audit_store, req, "scim.user.provenance_denied", "denied", scim_id,
             "no AuthDB configured");
        bump_provenance_denied(auth_mgr);
        return false;
    }
    auto source = db->get_provisioning_source(username);
    if (!source || *source != kProvisioningSourceScim) {
        spdlog::warn("SCIM: refusing to mutate account '{}' (scim_id={}) — "
                    "provisioning_source is not 'scim' (this account was not created by SCIM)",
                    username, scim_id);
        send_scim_error(res, 404, "resource not found");
        audit(auth_mgr, audit_store, req, "scim.user.provenance_denied", "denied", scim_id,
             "provisioning_source is not 'scim' for username=" + username);
        bump_provenance_denied(auth_mgr);
        return false;
    }
    return true;
}

/// H2 (2026-07-08 review, fail-open on a cold cache): read a user's role
/// AUTHORITATIVELY from `AuthDB`, never `AuthManager::get_user_role`'s
/// in-memory `users_` cache. That cache is populated lazily (login/upsert/
/// reactivate call sites) and nothing preloads it at process start, so a
/// freshly-booted server — or any process that has simply never touched
/// this username yet — reads back `nullopt` from the cache even when the
/// durable row is `admin`. The SCIM deprovision/revive guards previously
/// treated that `nullopt` as "no elevation on file, allowed", which is
/// fail-OPEN: a cold-cache process would deactivate a DB-elevated admin an
/// IdP pushes `active:false` for. Returns `nullopt` only when the role
/// genuinely cannot be determined (no `AuthDB` configured, or
/// `AuthDB::get_user` errors / finds no active row for `username`) —
/// every caller MUST treat `nullopt` as "refuse", never as "allowed"
/// (S-ROLE-FAILCLOSED).
std::optional<auth::Role> db_authoritative_role(auth::AuthManager* auth_mgr,
                                                const std::string& username) {
    AuthDB* db = auth_mgr ? auth_mgr->auth_db_ptr() : nullptr;
    if (!db)
        return std::nullopt;
    auto entry = db->get_user(username);
    if (!entry)
        return std::nullopt;
    return entry->role;
}

/// M-DEPROV-ROLE (sec MEDIUM): refuse to deprovision (deactivate/delete) an
/// account whose CURRENT role is not `user` — an operator who elevated a
/// SCIM-provisioned account to admin has taken its lifecycle out of SCIM's
/// read-only ownership model; SCIM only ever tears down what it still
/// recognises as its own. Checked only while the account is still ACTIVE.
/// Role is read via `db_authoritative_role` (H2) — the DB row, never the
/// AuthManager in-memory cache, which can be cold on a freshly-started
/// process. Returns true iff the deprovision may proceed; FAILS CLOSED
/// (refuses) if the role cannot be determined at all, not just when it
/// resolves to something other than `user`. On refusal sends 404 (never
/// 403 — matches the provenance guard's no-existence-oracle posture) and
/// reuses `scim.user.provenance_denied` (same "SCIM does not own this
/// account's lifecycle right now" refusal class).
bool deprovision_role_ok(auth::AuthManager* auth_mgr, AuditStore* audit_store,
                        const httplib::Request& req, const std::string& username,
                        const std::string& scim_id, httplib::Response& res) {
    auto role = db_authoritative_role(auth_mgr, username);
    if (!role.has_value() || *role != auth::Role::user) {
        spdlog::warn("SCIM: refusing to deprovision '{}' (scim_id={}) — role is not 'user' or "
                    "could not be authoritatively determined (an operator may have elevated "
                    "this account outside SCIM's ownership, or the DB-authoritative role read "
                    "failed closed)",
                    username, scim_id);
        send_scim_error(res, 404, "resource not found");
        audit(auth_mgr, audit_store, req, "scim.user.provenance_denied", "denied", scim_id,
             "role is not 'user' (or undetermined) for username=" + username);
        bump_provenance_denied(auth_mgr);
        return false;
    }
    return true;
}

/// Deactivate the auth account backing `resource` (provenance- and role-
/// guarded) and mark the SCIM resource inactive. Shared by PATCH
/// active=false, PUT active=false, and DELETE. Returns false (and has
/// already sent a response) on provenance/role refusal, an AuthManager
/// failure, or a ScimStore mirror-write failure (M-ATOMICITY, UP-5). A
/// failed termination audit does NOT fail the call — see `audit()`'s doc
/// comment (set-and-proceed, CC6.8 enforced via the failure-counter alert).
bool deactivate(ScimStore* scim_store, auth::AuthManager* auth_mgr, AuditStore* audit_store,
                const httplib::Request& req, httplib::Response& res, const ScimResource& resource,
                const std::string& audit_action) {
    if (!provenance_ok(auth_mgr, audit_store, req, resource.username, resource.scim_id, res))
        return false;
    if (!deprovision_role_ok(auth_mgr, audit_store, req, resource.username, resource.scim_id, res))
        return false;
    if (!auth_mgr->remove_user(resource.username)) {
        spdlog::error("ScimRoutes: AuthManager::remove_user failed for '{}' (scim_id={})",
                     resource.username, resource.scim_id);
        send_scim_error(res, 500, "failed to deactivate the underlying account");
        audit(auth_mgr, audit_store, req, audit_action, "failure", resource.scim_id);
        return false;
    }
    // M-ATOMICITY (UP-5): the AuthManager (AuthDB connection) write above
    // succeeded; now persist the SCIM-side mirror on ScimStore's SEPARATE
    // connection. If THIS write fails, the auth account is already
    // deactivated but the SCIM resource still reports active=true — fail
    // closed (500) so the IdP retries. The DB-level write inside
    // remove_user() is idempotent (its `UPDATE ... is_active = 0` re-applies
    // cleanly against an already-inactive row), and its bool *return value*
    // now agrees: AuthDB::remove_user's `RETURNING 1` matches on
    // `WHERE username = ?` alone, so it fires — and the return value reads
    // true — for any extant row regardless of `is_active`, i.e. idempotent-
    // true on a second call too, not "no-op success" vs. false. Retry safety
    // therefore does NOT rest on this return value distinguishing first vs.
    // repeat calls — it comes from the handler's re-fetch-and-skip at every
    // call site (`deactivate()` is only invoked when the freshly-fetched
    // `resource->active` is still true — see the PATCH/PUT/DELETE call
    // sites). The irreducible window between the two writes (a crash/kill
    // exactly between them) is a documented residual — reconciled by the
    // IdP's next full sync.
    if (!scim_store->set_active(resource.scim_id, false)) {
        spdlog::error("ScimRoutes: ScimStore::set_active(false) failed for scim_id={} after the "
                     "underlying account was already deactivated — inconsistent state, failing "
                     "closed so the IdP retries",
                     resource.scim_id);
        send_scim_error(res, 500, "failed to persist the deactivated state");
        audit(auth_mgr, audit_store, req, audit_action, "failure", resource.scim_id,
             "auth account deactivated but scim_resource mirror write failed");
        return false;
    }
    // Set-and-proceed (UP-N2): the mutation above already committed — a lost
    // audit row does not change that, and a fail-closed 500 here cannot
    // re-land it (the IdP's retry would observe active=false and take the
    // non-termination branch, never re-attempting this audit write). CC6.8
    // evidence integrity is enforced by an alert on
    // `yuzu_scim_audit_write_failures_total` (bumped inside `audit()` on
    // every failure), not by refusing to report the 2xx that already
    // happened.
    audit(auth_mgr, audit_store, req, audit_action, "success", resource.scim_id);
    return true;
}

/// Reactivate the auth account backing `resource` (provenance-guarded) and
/// mark the SCIM resource active again. Shared by PATCH active=true and PUT
/// active=true — the un-suspend counterpart of `deactivate`. The provenance
/// guard applies here too: reactivation is itself a mutation of the auth
/// account, so it must be refused (404) if the account isn't SCIM-owned —
/// same reasoning as deactivate/delete. Returns false (and has already sent
/// a response) on provenance refusal, an AuthManager failure, or a ScimStore
/// mirror-write failure (M-ATOMICITY). A failed termination-class audit does
/// NOT fail the call — see `audit()`'s doc comment (set-and-proceed, CC6.8
/// enforced via the failure-counter alert).
bool reactivate(ScimStore* scim_store, auth::AuthManager* auth_mgr, AuditStore* audit_store,
                const httplib::Request& req, httplib::Response& res, const ScimResource& resource) {
    if (!provenance_ok(auth_mgr, audit_store, req, resource.username, resource.scim_id, res))
        return false;
    if (!auth_mgr->reactivate_user(resource.username)) {
        spdlog::error("ScimRoutes: AuthManager::reactivate_user failed for '{}' (scim_id={})",
                     resource.username, resource.scim_id);
        send_scim_error(res, 500, "failed to reactivate the underlying account");
        audit(auth_mgr, audit_store, req, "scim.user.reactivated", "failure", resource.scim_id);
        return false;
    }
    if (!scim_store->set_active(resource.scim_id, true)) {
        spdlog::error("ScimRoutes: ScimStore::set_active(true) failed for scim_id={} after the "
                     "underlying account was already reactivated — inconsistent state, failing "
                     "closed so the IdP retries",
                     resource.scim_id);
        send_scim_error(res, 500, "failed to persist the reactivated state");
        audit(auth_mgr, audit_store, req, "scim.user.reactivated", "failure", resource.scim_id,
             "auth account reactivated but scim_resource mirror write failed");
        return false;
    }
    // Set-and-proceed (UP-N2) — see the matching comment in `deactivate()`.
    audit(auth_mgr, audit_store, req, "scim.user.reactivated", "success", resource.scim_id);
    return true;
}

} // namespace

void ScimRoutes::register_routes(httplib::Server& svr, ScimStore* scim_store,
                                 auth::AuthManager* auth_mgr, AuditStore* audit_store) {
    HttplibRouteSink sink(svr);
    register_routes(sink, scim_store, auth_mgr, audit_store);
}

void ScimRoutes::register_routes(HttpRouteSink& sink, ScimStore* scim_store,
                                 auth::AuthManager* auth_mgr, AuditStore* audit_store) {
    spdlog::info("SCIM routes: registering /scim/v2/* (provisioning surface)");

    // ── Discovery documents — PUBLIC-behind-the-bearer-gate (least exposure:
    // even the capability documents require the token, matching every other
    // /scim/v2/* route rather than carving out an unauthenticated exception). ──

    sink.Get("/scim/v2/ServiceProviderConfig",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res))
                    return;
                res.set_content(scim::service_provider_config().dump(), kScimJson);
            });

    sink.Get("/scim/v2/ResourceTypes",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res))
                    return;
                res.set_content(scim::resource_types().dump(), kScimJson);
            });

    sink.Get("/scim/v2/Schemas",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res))
                    return;
                res.set_content(scim::schemas().dump(), kScimJson);
            });

    // ── POST /scim/v2/Users — provision. ──────────────────────────────────

    sink.Post("/scim/v2/Users", [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                                    httplib::Response& res) {
        if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
            record_request(auth_mgr, "create", res.status);
            return;
        }
        if (req.body.size() > kMaxBodyBytes) {
            send_scim_error(res, 413, "request body too large");
            record_request(auth_mgr, "create", 413);
            return;
        }
        json body;
        try {
            body = json::parse(req.body);
        } catch (const std::exception&) {
            send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
            record_request(auth_mgr, "create", 400);
            return;
        }
        auto parsed = scim::parse_user(body);
        if (!parsed) {
            send_scim_error(res, parsed.error());
            record_request(auth_mgr, "create", parsed.error().status);
            return;
        }
        const auto& input = *parsed;
        if (!is_valid_username(input.user_name)) {
            send_scim_error(res, 400,
                           "userName is not a valid Yuzu username (1-64 chars, alnum/._-)",
                           "invalidValue");
            record_request(auth_mgr, "create", 400);
            return;
        }

        // Step 1 (unchanged): a LIVE scim_resource row means this identity
        // is provisioned RIGHT NOW — a re-POST for an already-provisioned
        // (active OR PATCH-deactivated-but-not-DELETEd) identity is a
        // protocol error; the IdP should PATCH/PUT instead.
        if (scim_store->get_by_username(input.user_name).has_value()) {
            send_scim_error(res, 409, "userName already exists", "uniqueness");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "denied", input.user_name,
                 "userName already exists");
            record_request(auth_mgr, "create", 409);
            return;
        }

        // Step 2 (M-LIFECYCLE — revive-on-reprovision): no live scim_resource
        // row, so decide fresh-create vs. revive vs. refuse from
        // provisioning_source, read INCLUSIVE of inactive rows
        // (get_provisioning_source's contract) so a DELETE-then-re-POST
        // tombstone and a half-create orphan both read back "scim" here —
        // exactly the state a returning employee's account is in
        // (fixes UP-1/2/3's deadlock: previously DELETE removed the
        // scim_resource but ON CONFLICT DO NOTHING made re-provisioning via
        // POST permanently fail).
        // FIX-2 (Hermes LOW): auth_mgr is a raw pointer threaded through from
        // the server's wiring — every other handler on this surface derefs
        // it freely too, but provenance_ok() (below, indirectly reached from
        // PATCH/PUT/DELETE) guards it explicitly before calling
        // auth_db_ptr(). Match that posture here at this handler's first
        // direct deref, rather than trust a caller-supplied non-null.
        if (!auth_mgr) {
            spdlog::error("ScimRoutes: cannot provision '{}' — no AuthManager configured",
                         input.user_name);
            send_scim_error(res, 500, "SCIM provisioning is unavailable (no AuthManager configured)");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure", input.user_name);
            record_request(auth_mgr, "create", 500);
            return;
        }
        AuthDB* db = auth_mgr->auth_db_ptr();
        if (!db) {
            spdlog::error("ScimRoutes: cannot provision '{}' — no AuthDB configured (SCIM "
                         "provisioning requires durable provenance tracking)",
                         input.user_name);
            send_scim_error(res, 500, "SCIM provisioning is unavailable (no AuthDB configured)");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure", input.user_name);
            record_request(auth_mgr, "create", 500);
            return;
        }
        auto source_result = db->get_provisioning_source(input.user_name);
        if (source_result.has_value() && *source_result != kProvisioningSourceScim) {
            // A local (or otherwise-sourced) account already owns this
            // username — SCIM must never adopt it (S-UNIQUE-DBREAD: this DB
            // read also catches a SOFT-DELETED local account the in-memory
            // get_user_role cache would have missed).
            send_scim_error(res, 409, "userName already exists", "uniqueness");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "denied", input.user_name,
                 "userName already exists (non-SCIM account)");
            record_request(auth_mgr, "create", 409);
            return;
        }

        // UP-N1 (FIX-1): tracks whether THIS call is the one that created the
        // auth row (the fresh-create branch below) vs. revived a pre-existing
        // one — gates the create_resource-failure rollback further down so a
        // concurrent revive's rollback can never deactivate a DIFFERENT
        // call's winning account.
        bool created_auth_row_this_call = false;

        if (source_result.has_value()) {
            // REVIVE: a tombstoned or half-created SCIM account this IdP
            // previously provisioned. Reactivate the EXISTING auth row —
            // never upsert_user again (that would UserAlreadyExists
            // pointlessly, and reactivate_user is the correct idempotent
            // primitive: it does not touch credentials/rotate the discard
            // password).
            if (!auth_mgr->reactivate_user(input.user_name)) {
                spdlog::error("ScimRoutes: reactivate_user failed reviving '{}'",
                             input.user_name);
                send_scim_error(res, 500, "failed to revive the underlying account");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 500);
                return;
            }

            // UP-N5 (FIX-5, defensive): reactivate_user() leaves `role`
            // untouched. If an operator elevated this account before it was
            // tombstoned, its role is still whatever they set it to —
            // SCIM's model owns only read-only 'user' accounts, so do not
            // resurrect an out-of-band-elevated account through the revive
            // path. Checked AFTER reactivate_user() (not before): the
            // tombstoned row is soft-deleted, so a plain cache read has no
            // entry for it until reactivate_user() loads it. Role is read
            // via `db_authoritative_role` (H2, consistency with
            // deprovision_role_ok) — the DB row, never the AuthManager
            // in-memory cache — and FAILS CLOSED (refuses) if the role
            // cannot be determined at all, not just when it resolves to
            // something other than 'user'. On refusal, undo the
            // reactivation (remove_user) so "refuse" actually means the
            // account stays down, not just that this response says 404.
            // Same posture as the deprovision role guard: 404 (never 403 —
            // no existence oracle), scim.user.provenance_denied.
            if (auto role = db_authoritative_role(auth_mgr, input.user_name);
                !role.has_value() || *role != auth::Role::user) {
                spdlog::warn("ScimRoutes: refusing to revive '{}' via POST — role is not "
                            "'user' (an operator elevated this account before it was "
                            "tombstoned)",
                            input.user_name);
                if (!auth_mgr->remove_user(input.user_name)) {
                    // remove_user() writes the DB first and returns false if
                    // that write failed (same contract as deactivate()'s
                    // check, above). Unchecked, a failure here would leave
                    // the account ACTIVE at its elevated role while this
                    // handler still claims 404 "resource not found" — and
                    // since 404 isn't retried by the IdP, the elevated
                    // account would stay reactivated indefinitely
                    // (privilege fail-open). Fail closed (500) instead so
                    // the IdP retries the whole POST.
                    spdlog::error("ScimRoutes: remove_user failed undoing the revive-role-"
                                 "refusal for '{}' — account remains ACTIVE at an elevated "
                                 "role",
                                 input.user_name);
                    send_scim_error(res, 500, "failed to revive the underlying account");
                    audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                         input.user_name,
                         "role-refusal undo (remove_user) failed — account left active at "
                         "an elevated role");
                    record_request(auth_mgr, "create", 500);
                    return;
                }
                send_scim_error(res, 404, "resource not found");
                audit(auth_mgr, audit_store, req, "scim.user.provenance_denied", "denied",
                     input.user_name, "role is not 'user' for username=" + input.user_name);
                bump_provenance_denied(auth_mgr);
                record_request(auth_mgr, "create", 404);
                return;
            }
        } else {
            // FRESH create (UP-9 duplicate-POST race handled below).
            // SCIM-provisioned accounts authenticate via the IdP/SSO only —
            // mint a long CSPRNG password and discard it immediately so
            // local password login is unusable (an unknowable password, not
            // a weak one). Always provisioned at the read-only 'user' role.
            std::vector<uint8_t> pw_bytes;
            try {
                pw_bytes = auth::AuthManager::random_bytes(32);
            } catch (const std::exception& e) {
                // S-RANDBYTES: random_bytes throws on a CSPRNG/RAND_bytes
                // failure — catch rather than let it unwind to a bare 500.
                spdlog::error(
                    "ScimRoutes: CSPRNG failure minting a discard password for '{}': {}",
                    input.user_name, e.what());
                send_scim_error(res, 503, "temporarily unable to provision (CSPRNG unavailable)");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 503);
                return;
            }
            auto discard_password = auth::AuthManager::bytes_to_hex(pw_bytes);
            if (!auth_mgr->upsert_user(input.user_name, discard_password, auth::Role::user)) {
                // UP-9: distinguish a genuine DB failure from a concurrent
                // duplicate POST that won the race between the uniqueness
                // check above and this write — re-read: if the account now
                // resolves, someone else just created it.
                if (auth_mgr->get_user_role(input.user_name).has_value()) {
                    send_scim_error(res, 409, "userName already exists", "uniqueness");
                    audit(auth_mgr, audit_store, req, "scim.user.provisioned", "denied",
                         input.user_name, "userName already exists (concurrent create)");
                    record_request(auth_mgr, "create", 409);
                    return;
                }
                send_scim_error(res, 500, "failed to create the underlying account");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 500);
                return;
            }
            created_auth_row_this_call = true;

            // S-IDENTITY-SRC: SCIM is its own login surface (IdP-driven SSO,
            // no usable local password) — distinct from the v6 'local'
            // default, which would render this account as local-login-
            // capable in the Settings UI. Best-effort: a failure here
            // doesn't block provisioning (the account still functions; only
            // the Settings UI badge would be wrong).
            if (auto r = db->set_identity_source(input.user_name, "scim"); !r) {
                spdlog::warn("ScimRoutes: set_identity_source failed for '{}' — the account "
                            "will still function, but the Settings UI may misrender its login "
                            "surface",
                            input.user_name);
            }

            // M-ORPHAN (UP-6/B1): set provenance BEFORE creating the
            // scim_resource row, and roll back the just-created auth account
            // if it fails — never leave an orphaned account with no SCIM
            // mapping AND no provenance marker (unmanageable by SCIM
            // forever after — a future revive attempt would read
            // provisioning_source=='local' and refuse it).
            if (auto r = db->set_provisioning_source(input.user_name,
                                                     std::string(kProvisioningSourceScim));
                !r) {
                spdlog::error("ScimRoutes: set_provisioning_source failed for '{}', rolling back",
                             input.user_name);
                auth_mgr->remove_user(input.user_name);
                send_scim_error(res, 500, "failed to record provisioning provenance");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 500);
                return;
            }
        }

        auto resource = scim_store->create_resource(input.user_name, input.external_id);
        if (!resource) {
            // UP-N1 (FIX-1): create_resource() returns nullopt on a
            // UNIQUE(username) conflict OR a genuine CSPRNG/db failure — the
            // two demand opposite responses, so distinguish them by
            // re-reading. If a live scim_resource mapping now exists, a
            // CONCURRENT re-POST for the same identity already won the race
            // between Step 1's uniqueness check and this write and has
            // already created/revived its own account — that is the winner;
            // touch nothing here (in particular, do NOT remove_user, which
            // would silently deactivate the winner's freshly-provisioned
            // account: 201 to them, no error, no retry, but is_active=0).
            if (scim_store->get_by_username(input.user_name).has_value()) {
                send_scim_error(res, 409, "userName already exists", "uniqueness");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "denied",
                     input.user_name, "userName already exists (concurrent revive/create)");
                record_request(auth_mgr, "create", 409);
                return;
            }
            // No mapping — a genuine create failure. Roll back to a
            // deactivated tombstone ONLY if THIS call created the auth row
            // (the fresh-create branch): the next POST for the same
            // userName retries this exact step (provisioning_source ==
            // "scim" still holds). In the REVIVE branch the account
            // pre-existed before this call — do NOT remove_user; leave the
            // just-reactivated row as-is so the IdP's retry re-enters the
            // revive branch above and adopts it (rolling it back here would
            // just re-tombstone an account the retry has to re-revive for no
            // benefit, and risks racing a DIFFERENT concurrent caller that
            // is also reviving the same identity).
            if (created_auth_row_this_call)
                auth_mgr->remove_user(input.user_name);
            send_scim_error(res, 500, "failed to create the SCIM resource mapping");
            audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                 input.user_name);
            record_request(auth_mgr, "create", 500);
            return;
        }

        // Honour an explicit active:false on create (some IdPs stage a user
        // deactivated) by immediately deactivating the account we just
        // made/revived.
        if (input.active.has_value() && !*input.active) {
            if (!auth_mgr->remove_user(input.user_name)) {
                // FIX-1 (Hermes MEDIUM, fail-open): previously this branch
                // only logged and fell through to set_active(false) below,
                // so a failed deactivation still shipped a 201 with
                // active:false while the underlying auth account stayed
                // LIVE — the IdP believes the user is deactivated when it
                // is not. Fail closed (500) and stop here, mirroring
                // deactivate()'s remove_user-failure branch above.
                spdlog::error("ScimRoutes: remove_user failed honouring active:false on create "
                             "for '{}' — the account remains active",
                             input.user_name);
                send_scim_error(res, 500, "failed to deactivate the underlying account");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name,
                     "active:false on create — remove_user failed, account left active");
                record_request(auth_mgr, "create", 500);
                return;
            }
            // UP-N3 (FIX-3): check the ScimStore mirror write — previously
            // unchecked, so a failure here silently shipped a 201 body
            // claiming active:true while the underlying account was already
            // deactivated. Fail closed (500); the IdP retries the whole
            // POST, which now sees the live mapping at Step 1 (409) or, if
            // the account genuinely ends up torn down first, the revive
            // path — either way the retry reconciles it.
            if (!scim_store->set_active(resource->scim_id, false)) {
                spdlog::error("ScimRoutes: ScimStore::set_active(false) failed honouring "
                             "active:false on create for scim_id={} — inconsistent state, "
                             "failing closed so the IdP retries",
                             resource->scim_id);
                send_scim_error(res, 500, "failed to persist the deactivated state");
                audit(auth_mgr, audit_store, req, "scim.user.provisioned", "failure",
                     input.user_name);
                record_request(auth_mgr, "create", 500);
                return;
            }
            // S-POST-REFETCH: re-fetch so the 201 body's ETag/meta.version/
            // lastModified reflect the bump set_active just made — PUT/PATCH
            // already re-fetch after their own mutations; mirror that here
            // so a later GET can't disagree with what this response claimed.
            if (auto refreshed = scim_store->get_by_scim_id(resource->scim_id))
                resource = refreshed;
            else
                resource->active = false; // M-OPTDEREF fallback — shouldn't happen
        }

        auto base = location_base(req);
        res.status = 201;
        res.set_header("Location", base + "/" + resource->scim_id);
        res.set_header("ETag", "W/\"" + std::to_string(resource->etag_version) + "\"");
        res.set_content(scim::user_to_json(*resource, base).dump(), kScimJson);
        // set-and-proceed (every SCIM audit call is, per `audit()`'s doc
        // comment) — the 201 above already committed regardless of whether
        // this row persists.
        audit(auth_mgr, audit_store, req, "scim.user.provisioned", "success", resource->scim_id);
        record_request(auth_mgr, "create", 201);
    });

    // ── GET /scim/v2/Users/{id} ────────────────────────────────────────────

    sink.Get(R"(/scim/v2/Users/([0-9a-fA-F]+))",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                    record_request(auth_mgr, "get", res.status);
                    return;
                }
                auto id = req.matches[1].str();
                auto resource = scim_store->get_by_scim_id(id);
                if (!resource) {
                    send_scim_error(res, 404, "resource not found");
                    record_request(auth_mgr, "get", 404);
                    return;
                }
                res.set_content(scim::user_to_json(*resource, location_base(req)).dump(),
                               kScimJson);
                record_request(auth_mgr, "get", 200);
            });

    // ── GET /scim/v2/Users — list / filter. ───────────────────────────────

    sink.Get("/scim/v2/Users",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                    record_request(auth_mgr, "list", res.status);
                    return;
                }
                auto base = location_base(req);

                int start_index = 1;
                if (req.has_param("startIndex")) {
                    auto parsed =
                        parse_scim_int_param(res, req.get_param_value("startIndex"), "startIndex");
                    if (!parsed) {
                        record_request(auth_mgr, "list", 400);
                        return;
                    }
                    start_index = *parsed;
                    // SCIM startIndex is 1-based (RFC 7644 §3.4.2); clamp
                    // anything below 1 up to the first page rather than
                    // echoing a negative/zero value back in the response.
                    if (start_index < 1)
                        start_index = 1;
                }
                int count = 100;
                if (req.has_param("count")) {
                    auto parsed = parse_scim_int_param(res, req.get_param_value("count"), "count");
                    if (!parsed) {
                        record_request(auth_mgr, "list", 400);
                        return;
                    }
                    count = *parsed;
                }
                // S-CLAMP-COUNT: never serve more than the maxResults this
                // server advertises in ServiceProviderConfig, regardless of
                // what the caller asks for.
                if (count > scim::kMaxScimListResults)
                    count = scim::kMaxScimListResults;

                if (req.has_param("filter")) {
                    auto filter_username = scim::parse_username_filter(req.get_param_value("filter"));
                    if (!filter_username) {
                        send_scim_error(res, filter_username.error());
                        record_request(auth_mgr, "list", filter_username.error().status);
                        return;
                    }
                    std::vector<json> resources;
                    int total = 0;
                    if (auto resource = scim_store->get_by_username(*filter_username)) {
                        resources.push_back(scim::user_to_json(*resource, base));
                        total = 1;
                    }
                    res.set_content(
                        scim::list_response(resources, total, 1,
                                           static_cast<int>(resources.size()))
                            .dump(),
                        kScimJson);
                    record_request(auth_mgr, "list", 200);
                    return;
                }

                int total = 0;
                auto page = scim_store->list(start_index, count, total);
                std::vector<json> resources;
                resources.reserve(page.size());
                for (const auto& r : page)
                    resources.push_back(scim::user_to_json(r, base));
                res.set_content(scim::list_response(resources, total, start_index,
                                                    static_cast<int>(resources.size()))
                                    .dump(),
                                kScimJson);
                record_request(auth_mgr, "list", 200);
            });

    // ── PUT /scim/v2/Users/{id} — full replace (identity fields only). ────

    sink.Put(R"(/scim/v2/Users/([0-9a-fA-F]+))",
            [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                httplib::Response& res) {
                if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                    record_request(auth_mgr, "replace", res.status);
                    return;
                }
                auto id = req.matches[1].str();
                auto resource = scim_store->get_by_scim_id(id);
                if (!resource) {
                    send_scim_error(res, 404, "resource not found");
                    record_request(auth_mgr, "replace", 404);
                    return;
                }
                if (req.body.size() > kMaxBodyBytes) {
                    send_scim_error(res, 413, "request body too large");
                    record_request(auth_mgr, "replace", 413);
                    return;
                }
                json body;
                try {
                    body = json::parse(req.body);
                } catch (const std::exception&) {
                    send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
                    record_request(auth_mgr, "replace", 400);
                    return;
                }
                auto parsed = scim::parse_user(body);
                if (!parsed) {
                    send_scim_error(res, parsed.error());
                    record_request(auth_mgr, "replace", parsed.error().status);
                    return;
                }
                const auto& input = *parsed;

                // Rename is out of scope for slice 1 (the SCIM `id`, not
                // `userName`, is the stable identifier IdPs are expected to
                // key on going forward) — refuse rather than silently
                // ignoring the IdP's intent.
                if (input.user_name != resource->username) {
                    send_scim_error(res, 400,
                                   "userName change via PUT is not supported in this slice",
                                   "mutability");
                    record_request(auth_mgr, "replace", 400);
                    return;
                }

                bool active_transitioned = false;
                if (input.active.has_value() && !*input.active && resource->active) {
                    if (!deactivate(scim_store, auth_mgr, audit_store, req, res, *resource,
                                    "scim.user.deactivated")) {
                        record_request(auth_mgr, "replace", res.status);
                        return;
                    }
                    resource->active = false;
                    active_transitioned = true;
                } else if (input.active.has_value() && *input.active && !resource->active) {
                    if (!reactivate(scim_store, auth_mgr, audit_store, req, res, *resource)) {
                        record_request(auth_mgr, "replace", res.status);
                        return;
                    }
                    resource->active = true;
                    active_transitioned = true;
                } else if (input.active.has_value() && !*input.active && !resource->active) {
                    // FIX (MEDIUM-1, CC6.8 deprovision desync): the
                    // scim_resource mirror already reads inactive, but do
                    // not trust it blindly before taking the no-op
                    // short-circuit — a prior mirror-write failure (see
                    // deactivate()'s M-ATOMICITY comment) or an
                    // out-of-band reactivation could leave the underlying
                    // auth account genuinely LIVE while SCIM/the IdP
                    // believes it is already deprovisioned. Check the real
                    // auth state; only take the no-op when it is ALSO
                    // genuinely inactive.
                    if (auth_mgr->get_user_role(resource->username).has_value()) {
                        spdlog::warn(
                            "ScimRoutes: PUT active:false — scim_resource mirror for '{}' "
                            "(scim_id={}) says inactive but the auth account is still live; "
                            "re-running deactivation",
                            resource->username, resource->scim_id);
                        if (!deactivate(scim_store, auth_mgr, audit_store, req, res, *resource,
                                        "scim.user.deactivated")) {
                            record_request(auth_mgr, "replace", res.status);
                            return;
                        }
                        resource->active = false;
                        active_transitioned = true;
                    }
                    // else: genuinely already inactive — true no-op, no audit.
                }

                // L3 (2026-07-08 review): externalId-only mutation. The
                // active-transition branches above already re-verify both
                // guards via deactivate()/reactivate(), but a PUT that
                // leaves `active` unset/unchanged (or already reads false)
                // reaches this write with NO guard check at all — re-verify
                // provenance immediately before the mutating call so every
                // mutation on this surface, including an externalId-only
                // one, re-checks it (matches the doc's "every mutation
                // re-verifies" claim). The role check is gated on
                // `resource->active` (the CURRENT, post-transition state) —
                // same posture as the DELETE handler's already-inactive
                // branch: once the account is inactive there is nothing
                // further being torn down for the role guard to protect,
                // and `deprovision_role_ok` would otherwise fail closed on
                // every inactive-but-legitimately-SCIM-owned account (its
                // DB-authoritative read only resolves an ACTIVE row).
                if (!provenance_ok(auth_mgr, audit_store, req, resource->username,
                                   resource->scim_id, res)) {
                    record_request(auth_mgr, "replace", res.status);
                    return;
                }
                if (resource->active &&
                    !deprovision_role_ok(auth_mgr, audit_store, req, resource->username,
                                         resource->scim_id, res)) {
                    record_request(auth_mgr, "replace", res.status);
                    return;
                }
                if (!scim_store->update_resource(resource->scim_id, resource->username,
                                                 input.external_id)) {
                    send_scim_error(res, 500, "failed to update the SCIM resource mapping");
                    record_request(auth_mgr, "replace", 500);
                    return;
                }
                auto updated = scim_store->get_by_scim_id(resource->scim_id);
                if (!updated) {
                    // M-OPTDEREF (UP-4): a concurrent DELETE emptied the
                    // resource between the mutation above and this
                    // re-fetch. The mutation already committed — 500 (not
                    // 404, which would misleadingly imply "never existed").
                    spdlog::error("ScimRoutes: PUT — resource scim_id={} vanished mid-request",
                                 resource->scim_id);
                    send_scim_error(res, 500, "resource state changed mid-request");
                    record_request(auth_mgr, "replace", 500);
                    return;
                }
                if (!active_transitioned) {
                    // deactivate()/reactivate() already audited their own
                    // action (and already fail closed on their own audit
                    // failure); avoid a duplicate "updated" row for that
                    // case. "updated" itself is NOT a termination action —
                    // set-and-proceed.
                    audit(auth_mgr, audit_store, req, "scim.user.updated", "success",
                         resource->scim_id);
                }
                res.set_content(scim::user_to_json(*updated, location_base(req)).dump(),
                               kScimJson);
                record_request(auth_mgr, "replace", 200);
            });

    // ── PATCH /scim/v2/Users/{id} — the critical deprovision path. ────────

    sink.Patch(R"(/scim/v2/Users/([0-9a-fA-F]+))",
              [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                  httplib::Response& res) {
                  if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                      record_request(auth_mgr, "patch", res.status);
                      return;
                  }
                  auto id = req.matches[1].str();
                  auto resource = scim_store->get_by_scim_id(id);
                  if (!resource) {
                      send_scim_error(res, 404, "resource not found");
                      record_request(auth_mgr, "patch", 404);
                      return;
                  }
                  if (req.body.size() > kMaxBodyBytes) {
                      send_scim_error(res, 413, "request body too large");
                      record_request(auth_mgr, "patch", 413);
                      return;
                  }
                  json body;
                  try {
                      body = json::parse(req.body);
                  } catch (const std::exception&) {
                      send_scim_error(res, 400, "request body is not valid JSON", "invalidValue");
                      record_request(auth_mgr, "patch", 400);
                      return;
                  }
                  auto parsed = scim::parse_patch(body);
                  if (!parsed) {
                      send_scim_error(res, parsed.error());
                      record_request(auth_mgr, "patch", parsed.error().status);
                      return;
                  }
                  const auto& patch = *parsed;

                  // Validate the unsupported-mutation case BEFORE applying
                  // anything else, so a body combining an unsupported
                  // userName change with a supported active/externalId
                  // change can't leave a partial mutation committed behind
                  // a 400 response.
                  if (patch.user_name.has_value() && *patch.user_name != resource->username) {
                      send_scim_error(res, 400,
                                     "userName change via PATCH is not supported in this slice",
                                     "mutability");
                      record_request(auth_mgr, "patch", 400);
                      return;
                  }

                  bool active_transitioned = false;
                  if (patch.active.has_value()) {
                      if (!*patch.active && resource->active) {
                          if (!deactivate(scim_store, auth_mgr, audit_store, req, res, *resource,
                                          "scim.user.deactivated")) {
                              record_request(auth_mgr, "patch", res.status);
                              return;
                          }
                          resource->active = false;
                          active_transitioned = true;
                      } else if (*patch.active && !resource->active) {
                          if (!reactivate(scim_store, auth_mgr, audit_store, req, res,
                                         *resource)) {
                              record_request(auth_mgr, "patch", res.status);
                              return;
                          }
                          resource->active = true;
                          active_transitioned = true;
                      } else if (!*patch.active && !resource->active) {
                          // FIX (MEDIUM-1, CC6.8 deprovision desync): same
                          // reasoning as the PUT active:false no-op branch
                          // — verify the real auth state before trusting
                          // the mirror's "already inactive" and short-
                          // circuiting to a no-op.
                          if (auth_mgr->get_user_role(resource->username).has_value()) {
                              spdlog::warn(
                                  "ScimRoutes: PATCH active:false — scim_resource mirror for "
                                  "'{}' (scim_id={}) says inactive but the auth account is "
                                  "still live; re-running deactivation",
                                  resource->username, resource->scim_id);
                              if (!deactivate(scim_store, auth_mgr, audit_store, req, res,
                                              *resource, "scim.user.deactivated")) {
                                  record_request(auth_mgr, "patch", res.status);
                                  return;
                              }
                              resource->active = false;
                              active_transitioned = true;
                          }
                          // else: genuinely already inactive — true no-op, no audit.
                      }
                      // else: no-op (active:true already reads active — no
                      // desync risk on the reactivate path).
                  }

                  if (patch.external_id.has_value()) {
                      // L3 (2026-07-08 review): same reasoning as the PUT
                      // externalId-update path above — a PATCH carrying
                      // only `externalId` (no `active` op) reached this
                      // write with no guard check at all. Role check gated
                      // on the CURRENT `resource->active`: matches the
                      // DELETE handler's already-inactive posture (nothing
                      // further being torn down once inactive, and
                      // `deprovision_role_ok` only resolves an ACTIVE row).
                      if (!provenance_ok(auth_mgr, audit_store, req, resource->username,
                                        resource->scim_id, res)) {
                          record_request(auth_mgr, "patch", res.status);
                          return;
                      }
                      if (resource->active &&
                          !deprovision_role_ok(auth_mgr, audit_store, req, resource->username,
                                              resource->scim_id, res)) {
                          record_request(auth_mgr, "patch", res.status);
                          return;
                      }
                      if (!scim_store->update_resource(resource->scim_id, resource->username,
                                                       *patch.external_id)) {
                          send_scim_error(res, 500, "failed to update the SCIM resource mapping");
                          record_request(auth_mgr, "patch", 500);
                          return;
                      }
                  }

                  auto updated = scim_store->get_by_scim_id(resource->scim_id);
                  if (!updated) {
                      // M-OPTDEREF (UP-4): a concurrent DELETE emptied the
                      // resource between the mutation above and this
                      // re-fetch.
                      spdlog::error("ScimRoutes: PATCH — resource scim_id={} vanished "
                                   "mid-request",
                                   resource->scim_id);
                      send_scim_error(res, 500, "resource state changed mid-request");
                      record_request(auth_mgr, "patch", 500);
                      return;
                  }
                  if (!active_transitioned) {
                      // deactivate()/reactivate() already audited their own
                      // action; avoid a duplicate "updated" row for that
                      // case.
                      audit(auth_mgr, audit_store, req, "scim.user.updated", "success",
                           resource->scim_id);
                  }
                  res.set_content(scim::user_to_json(*updated, location_base(req)).dump(),
                                 kScimJson);
                  record_request(auth_mgr, "patch", 200);
              });

    // ── DELETE /scim/v2/Users/{id} ─────────────────────────────────────────

    sink.Delete(R"(/scim/v2/Users/([0-9a-fA-F]+))",
               [scim_store, auth_mgr, audit_store](const httplib::Request& req,
                                                   httplib::Response& res) {
                   if (!require_bearer(scim_store, auth_mgr, audit_store, req, res)) {
                       record_request(auth_mgr, "delete", res.status);
                       return;
                   }
                   auto id = req.matches[1].str();
                   auto resource = scim_store->get_by_scim_id(id);
                   if (!resource) {
                       send_scim_error(res, 404, "resource not found");
                       record_request(auth_mgr, "delete", 404);
                       return;
                   }
                   if (resource->active) {
                       if (!provenance_ok(auth_mgr, audit_store, req, resource->username, id,
                                         res)) {
                           record_request(auth_mgr, "delete", res.status);
                           return;
                       }
                       if (!deprovision_role_ok(auth_mgr, audit_store, req, resource->username,
                                               id, res)) {
                           record_request(auth_mgr, "delete", res.status);
                           return;
                       }
                       if (!auth_mgr->remove_user(resource->username)) {
                           send_scim_error(res, 500, "failed to deactivate the underlying account");
                           audit(auth_mgr, audit_store, req, "scim.user.deleted", "failure", id);
                           record_request(auth_mgr, "delete", 500);
                           return;
                       }
                   } else {
                       // Already deactivated — still re-verify provenance
                       // before the DELETE removes the mapping row, so a
                       // scim_resource somehow pointing at a non-SCIM
                       // account still can't be wiped out from under it. No
                       // role re-check here: the account is already
                       // inactive, so there is nothing further being torn
                       // down (see deprovision_role_ok's doc comment — the
                       // in-memory role cache has no entry to check anyway).
                       if (!provenance_ok(auth_mgr, audit_store, req, resource->username, id,
                                         res)) {
                           record_request(auth_mgr, "delete", res.status);
                           return;
                       }
                   }

                   // M-ATOMICITY (UP-5): check the ScimStore write too. On
                   // the resource->active branch above, the AuthManager
                   // write already succeeded — a failure here leaves the
                   // account deactivated but the mapping row still present.
                   // delete_by_scim_id's tri-state return distinguishes a
                   // real DB error (nullopt — fail closed below so the IdP
                   // retries) from "the mapping row is already gone" (false
                   // — a concurrent/duplicate DELETE beat us to it; UP-N4/
                   // FIX-4: that is idempotent SUCCESS, not a failure — the
                   // account is deleted either way). Retry safety for the
                   // resource->active branch above comes from the handler's
                   // own re-fetch-and-skip (a retry sees resource->active ==
                   // false and takes the already-deactivated branch instead
                   // of re-calling remove_user), not from remove_user()
                   // itself being a true no-op — see deactivate()'s
                   // M-ATOMICITY comment for why that distinction matters.
                   auto delete_result = scim_store->delete_by_scim_id(id);
                   if (!delete_result.has_value()) {
                       spdlog::error("ScimRoutes: ScimStore::delete_by_scim_id failed for "
                                    "scim_id={}",
                                    id);
                       send_scim_error(res, 500, "failed to remove the SCIM resource mapping");
                       audit(auth_mgr, audit_store, req, "scim.user.deleted", "failure", id);
                       record_request(auth_mgr, "delete", 500);
                       return;
                   }
                   if (!*delete_result) {
                       spdlog::info("ScimRoutes: DELETE scim_id={} — mapping row already gone "
                                   "(concurrent/duplicate DELETE); treating as idempotent "
                                   "success",
                                   id);
                   }
                   // Set-and-proceed (UP-N2) — see the matching comment in
                   // `deactivate()`.
                   audit(auth_mgr, audit_store, req, "scim.user.deleted", "success", id);
                   res.status = 204;
                   record_request(auth_mgr, "delete", 204);
               });
}

} // namespace yuzu::server
