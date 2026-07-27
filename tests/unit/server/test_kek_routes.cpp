/**
 * test_kek_routes.cpp — HTTP-level coverage for the KEK (key-encryption-key)
 * rotation REST surface under POST/GET /api/v1/secrets/kek/... (#2395 track D).
 *
 * Modelled on test_ca_routes.cpp's Harness: registers KekRoutes against an
 * in-process TestRouteSink (no socket, TSan-safe, #438) with a fully
 * controllable STUB `KekOps` — no Postgres, no SecretCodec, so every
 * `KekOpResult::Failure` can be driven deterministically. None of these
 * cases carry `[pg]` — see the codec-level tests in test_secret_codec.cpp
 * for the real Postgres-backed rotation/rewrap behaviour.
 *
 * Coverage: permission gates (Security:Write for rotate/rewrap, Security:Read
 * for status) and their short-circuit; every failure->HTTP-status mapping;
 * the HalfCommitted remediation string (#2395 rule A: must send the caller
 * to /rewrap, must NOT invite a /rotate retry); no internal-error string
 * leak (#2395 rule B); unset/empty KekOps answering 503 without crashing;
 * audit rows (kek.rotate/kek.rewrap, target Secret/kek, Sec-Audit-Failed on
 * a dropped audit row, no audit row at all on the read-only /status route);
 * body handling (absent/`{}` body accepted, unknown key rejected, oversized
 * body rejected); and the /rotate response shape (new_version +
 * rotation_complete present, rows_rewrapped deliberately absent).
 */

#include "kek_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

struct AuditRow {
    std::string action, result, target_type, target_id, detail;
};

// Wires KekRoutes against an in-process sink with a fully-stubbed KekOps —
// no real codec/pool, so every KekOpResult::Failure is driven directly by
// the test. `rotate_set`/`rewrap_set`/`status_set` toggle whether the
// corresponding std::function is populated at all (unset -> route answers
// 503 without ever touching a stub).
struct Harness {
    test::TestRouteSink sink;
    std::vector<AuditRow> audits;
    bool perm_allow{true};
    bool audit_succeeds{true};
    std::string last_perm_type;
    std::string last_perm_op;

    bool rotate_set{true};
    bool rewrap_set{true};
    bool status_set{true};
    int rotate_calls{0};
    int rewrap_calls{0};
    int status_calls{0};
    KekOpResult rotate_result{};
    KekOpResult rewrap_result{};
    KekOpResult status_result{};

    void wire() {
        KekRoutes routes;
        KekRoutes::PermFn perm = [this](const httplib::Request&, httplib::Response& res,
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
        KekRoutes::AuditFn audit = [this](const httplib::Request&, const std::string& a,
                                          const std::string& r, const std::string& tt,
                                          const std::string& ti, const std::string& d) -> bool {
            audits.push_back({a, r, tt, ti, d});
            return audit_succeeds;
        };
        KekOps ops;
        if (rotate_set)
            ops.rotate = [this]() {
                ++rotate_calls;
                return rotate_result;
            };
        if (rewrap_set)
            ops.rewrap = [this]() {
                ++rewrap_calls;
                return rewrap_result;
            };
        if (status_set)
            ops.status = [this]() {
                ++status_calls;
                return status_result;
            };
        routes.register_routes(sink, perm, audit, std::move(ops));
    }
};

} // namespace

// ── Permission gates ──────────────────────────────────────────────────────

TEST_CASE("kek_routes: /rotate and /rewrap gate on Security:Write", "[kek_routes][security]") {
    Harness h;
    h.wire();

    auto rotate = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    CHECK(h.last_perm_type == "Security");
    CHECK(h.last_perm_op == "Write");

    auto rewrap = h.sink.Post("/api/v1/secrets/kek/rewrap", "");
    REQUIRE(rewrap);
    CHECK(h.last_perm_type == "Security");
    CHECK(h.last_perm_op == "Write");
}

TEST_CASE("kek_routes: /status gates on Security:Read", "[kek_routes][security]") {
    Harness h;
    h.wire();

    auto status = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(status);
    CHECK(h.last_perm_type == "Security");
    CHECK(h.last_perm_op == "Read");
}

TEST_CASE("kek_routes: a denying perm_fn short-circuits every route before the seam is touched",
          "[kek_routes][security]") {
    Harness h;
    h.perm_allow = false;
    h.wire();

    auto rotate = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    CHECK(rotate->status == 403);
    CHECK(h.rotate_calls == 0);

    auto rewrap = h.sink.Post("/api/v1/secrets/kek/rewrap", "");
    REQUIRE(rewrap);
    CHECK(rewrap->status == 403);
    CHECK(h.rewrap_calls == 0);

    auto status = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(status);
    CHECK(status->status == 403);
    CHECK(h.status_calls == 0);

    CHECK(h.audits.empty()); // denial happens before any audit_fn call
}

// ── Failure -> HTTP status mapping ───────────────────────────────────────

TEST_CASE("kek_routes: every KekOpResult::Failure maps to the documented HTTP status",
          "[kek_routes]") {
    struct Case {
        KekOpResult::Failure failure;
        int expected_status;
    };
    const Case cases[] = {
        {KekOpResult::Failure::Unavailable, 503},
        {KekOpResult::Failure::Conflict, 409},
        {KekOpResult::Failure::HalfCommitted, 500},
        {KekOpResult::Failure::Internal, 500},
    };

    for (const auto& c : cases) {
        INFO("rotate, failure=" << static_cast<int>(c.failure));
        Harness h;
        h.rotate_result.failure = c.failure;
        h.wire();
        auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
        REQUIRE(res);
        CHECK(res->status == c.expected_status);
    }

    for (const auto& c : cases) {
        INFO("rewrap, failure=" << static_cast<int>(c.failure));
        Harness h;
        h.rewrap_result.failure = c.failure;
        h.wire();
        auto res = h.sink.Post("/api/v1/secrets/kek/rewrap", "");
        REQUIRE(res);
        CHECK(res->status == c.expected_status);
    }

    for (const auto& c : cases) {
        INFO("status, failure=" << static_cast<int>(c.failure));
        Harness h;
        h.status_result.failure = c.failure;
        h.wire();
        auto res = h.sink.Get("/api/v1/secrets/kek/status");
        REQUIRE(res);
        CHECK(res->status == c.expected_status);
    }
}

TEST_CASE("kek_routes: an unset KekOps member answers 503 without ever being invoked",
          "[kek_routes]") {
    Harness h;
    h.rotate_set = false;
    h.rewrap_set = false;
    h.status_set = false;
    h.wire();

    auto rotate = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    CHECK(rotate->status == 503);
    CHECK(h.rotate_calls == 0);

    auto rewrap = h.sink.Post("/api/v1/secrets/kek/rewrap", "");
    REQUIRE(rewrap);
    CHECK(rewrap->status == 503);
    CHECK(h.rewrap_calls == 0);

    auto status = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(status);
    CHECK(status->status == 503);
    CHECK(h.status_calls == 0);
}

TEST_CASE("kek_routes: a default-constructed KekOps (every std::function unset) never crashes",
          "[kek_routes]") {
    // Not via Harness's per-field toggles (which still populate a lambda when
    // *_set is true) — register a genuinely default-constructed KekOps{}
    // directly, so an empty std::function invocation would be a std::bad_function_call
    // crash if the route ever dereferenced it without the `if (!ops.rotate)` guard.
    test::TestRouteSink sink;
    KekRoutes routes;
    KekRoutes::PermFn perm = [](const httplib::Request&, httplib::Response&,
                                const std::string&, const std::string&) { return true; };
    KekRoutes::AuditFn audit = [](const httplib::Request&, const std::string&, const std::string&,
                                  const std::string&, const std::string&,
                                  const std::string&) { return true; };
    routes.register_routes(sink, perm, audit, KekOps{});

    auto rotate = sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    CHECK(rotate->status == 503);

    auto rewrap = sink.Post("/api/v1/secrets/kek/rewrap", "");
    REQUIRE(rewrap);
    CHECK(rewrap->status == 503);

    auto status = sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(status);
    CHECK(status->status == 503);
}

// ── HalfCommitted remediation (#2395 rule A) ─────────────────────────────

TEST_CASE("kek_routes: HalfCommitted tells the caller to call /rewrap and NEVER invites a "
          "/rotate retry",
          "[kek_routes][security]") {
    Harness h;
    h.rotate_result.failure = KekOpResult::Failure::HalfCommitted;
    h.wire();

    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(res);
    REQUIRE(res->status == 500);
    auto body = json::parse(res->body);
    const std::string remediation = body["error"]["remediation"].get<std::string>();
    const std::string message = body["error"]["message"].get<std::string>();

    // MUST tell the caller to resume via /rewrap.
    CHECK(remediation.find("/api/v1/secrets/kek/rewrap") != std::string::npos);
    CHECK(remediation.find("resume") != std::string::npos);
    // The remediation legitimately MENTIONS /rotate once — as the "do NOT
    // retry" warning — so this must NEVER be a bare invitation: every mention
    // of "/rotate" must be preceded, on the same string, by an explicit
    // negation ("do NOT"/"do not"/"never").
    auto rotate_pos = remediation.find("/api/v1/secrets/kek/rotate");
    REQUIRE(rotate_pos != std::string::npos); // the warning itself must be present
    const std::string prefix = remediation.substr(0, rotate_pos);
    CHECK((prefix.find("do NOT") != std::string::npos || prefix.find("do not") != std::string::npos ||
           prefix.find("DO NOT") != std::string::npos || prefix.find("never") != std::string::npos ||
           prefix.find("Never") != std::string::npos));
    (void)message;
}

// ── No internal error string leak (#2395 rule B) ─────────────────────────

TEST_CASE("kek_routes: an Internal failure never leaks a database/codec-shaped string",
          "[kek_routes][security]") {
    // KekOpResult carries no string field at all for Internal — there is
    // structurally no channel for a codec-internal string to reach this
    // struct (kek_routes.hpp rule B). This test pins the OBSERVABLE
    // behaviour: the body is the fixed generic message, nothing else.
    Harness h;
    h.rotate_result.failure = KekOpResult::Failure::Internal;
    h.wire();

    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(res);
    REQUIRE(res->status == 500);
    auto body = json::parse(res->body);
    CHECK(body["error"]["message"].get<std::string>() == "internal error");

    // Positive assertion on the generic message rather than trying to
    // enumerate every possible leak shape.
    const std::string dumped = res->body;
    CHECK(dumped.find("PQerrorMessage") == std::string::npos);
    CHECK(dumped.find("postgres") == std::string::npos);
    CHECK(dumped.find("Postgres") == std::string::npos);
    CHECK(dumped.find("libpq") == std::string::npos);
    CHECK(dumped.find("SELECT") == std::string::npos);
    CHECK(dumped.find("relation \"") == std::string::npos); // Postgres's `relation "x" does not exist` shape
}

// ── Audit ─────────────────────────────────────────────────────────────────

TEST_CASE("kek_routes: a successful rotate/rewrap audits kek.rotate/kek.rewrap against "
          "Secret/kek",
          "[kek_routes][security]") {
    Harness h;
    h.rotate_result.new_version = 7;
    h.rotate_result.rotation_complete = true;
    h.wire();

    auto rotate = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    REQUIRE(rotate->status == 200);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "kek.rotate");
    CHECK(h.audits[0].result == "success");
    CHECK(h.audits[0].target_type == "Secret");
    CHECK(h.audits[0].target_id == "kek");

    Harness h2;
    h2.rewrap_result.rows_rewrapped = 3;
    h2.wire();
    auto rewrap = h2.sink.Post("/api/v1/secrets/kek/rewrap", "");
    REQUIRE(rewrap);
    REQUIRE(rewrap->status == 200);
    REQUIRE(h2.audits.size() == 1);
    CHECK(h2.audits[0].action == "kek.rewrap");
    CHECK(h2.audits[0].result == "success");
    CHECK(h2.audits[0].target_type == "Secret");
    CHECK(h2.audits[0].target_id == "kek");
}

TEST_CASE("kek_routes: a failing rotate/rewrap still audits a failure row against Secret/kek",
          "[kek_routes][security]") {
    Harness h;
    h.rotate_result.failure = KekOpResult::Failure::Conflict;
    h.wire();
    auto rotate = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    REQUIRE(rotate->status == 409);
    REQUIRE(h.audits.size() == 1);
    CHECK(h.audits[0].action == "kek.rotate");
    CHECK(h.audits[0].result == "failure");
    CHECK(h.audits[0].target_type == "Secret");
    CHECK(h.audits[0].target_id == "kek");
}

TEST_CASE("kek_routes: a dropped audit row on a successful rotate sets Sec-Audit-Failed",
          "[kek_routes][security]") {
    Harness h;
    h.audit_succeeds = false;
    h.wire();
    auto rotate = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(rotate);
    REQUIRE(rotate->status == 200); // the rotate itself still succeeded
    CHECK(rotate->get_header_value("Sec-Audit-Failed") == "true");
}

TEST_CASE("kek_routes: GET /status never emits an audit row, success or failure",
          "[kek_routes][security]") {
    Harness h;
    h.wire();
    auto ok = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(ok);
    REQUIRE(ok->status == 200);
    CHECK(h.audits.empty());

    Harness h2;
    h2.status_result.failure = KekOpResult::Failure::Internal;
    h2.wire();
    auto fail = h2.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(fail);
    REQUIRE(fail->status == 500);
    CHECK(h2.audits.empty());
}

// ── Body handling ─────────────────────────────────────────────────────────

TEST_CASE("kek_routes: rotate/rewrap accept both an absent body and an empty {} body",
          "[kek_routes]") {
    Harness h;
    h.wire();
    auto absent = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(absent);
    CHECK(absent->status == 200);

    Harness h2;
    h2.wire();
    auto empty_obj = h2.sink.Post("/api/v1/secrets/kek/rotate", "{}");
    REQUIRE(empty_obj);
    CHECK(empty_obj->status == 200);
}

TEST_CASE("kek_routes: a body with an unknown key is rejected 400 (mass-assignment guard)",
          "[kek_routes][security]") {
    Harness h;
    h.wire();
    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", R"({"force":true})");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(h.rotate_calls == 0); // the seam must never be reached
}

TEST_CASE("kek_routes: an oversized body is rejected 413 before JSON parsing", "[kek_routes]") {
    Harness h;
    h.wire();
    std::string big = R"({"pad":")" + std::string(70000, 'x') + R"("})";
    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", big);
    REQUIRE(res);
    CHECK(res->status == 413);
    CHECK(h.rotate_calls == 0);
}

// ── Response shape ─────────────────────────────────────────────────────────

TEST_CASE("kek_routes: /rotate's 200 body carries new_version + rotation_complete and "
          "deliberately omits rows_rewrapped",
          "[kek_routes]") {
    Harness h;
    h.rotate_result.new_version = 42;
    h.rotate_result.rotation_complete = true;
    h.rotate_result.rows_rewrapped = 99; // seam-internal value; must not leak into the body
    h.wire();

    auto res = h.sink.Post("/api/v1/secrets/kek/rotate", "");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["new_version"] == 42);
    CHECK(body["rotation_complete"] == true);
    CHECK_FALSE(body.contains("rows_rewrapped"));
}

TEST_CASE("kek_routes: /rewrap's 200 body carries rows_rewrapped", "[kek_routes]") {
    Harness h;
    h.rewrap_result.rows_rewrapped = 5;
    h.wire();
    auto res = h.sink.Post("/api/v1/secrets/kek/rewrap", "");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["rows_rewrapped"] == 5);
}

TEST_CASE("kek_routes: GET /status's 200 body carries active_version, oldest_in_use "
          "(null when absent), and rotation_complete",
          "[kek_routes]") {
    Harness h;
    h.status_result.active_version = 3;
    h.status_result.oldest_in_use = std::nullopt;
    h.status_result.rotation_complete = true;
    h.wire();
    auto res = h.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto body = json::parse(res->body);
    CHECK(body["active_version"] == 3);
    CHECK(body["oldest_in_use"].is_null());
    CHECK(body["rotation_complete"] == true);

    Harness h2;
    h2.status_result.active_version = 3;
    h2.status_result.oldest_in_use = 2;
    h2.status_result.rotation_complete = false;
    h2.wire();
    auto res2 = h2.sink.Get("/api/v1/secrets/kek/status");
    REQUIRE(res2);
    auto body2 = json::parse(res2->body);
    CHECK(body2["oldest_in_use"] == 2);
    CHECK(body2["rotation_complete"] == false);
}
