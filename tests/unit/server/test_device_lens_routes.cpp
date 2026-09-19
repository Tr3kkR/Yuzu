/// @file test_device_lens_routes.cpp
/// Route-level tests for the DEX + Guardian device-page lenses
/// (`/fragments/device/dex`, `/fragments/device/guardian`) — split out of
/// device_routes.cpp/test_device_routes.cpp by ADR-0031 WS-A4 wave 2 (see
/// device_lens_routes.hpp's file banner). Driven in-process through
/// TestRouteSink (no httplib acceptor, #438), with stub scoped-perm/audit fns
/// and a real (Postgres-backed) GuaranteedStateStore where the lens actually
/// reads store data.

#include "device_lens_routes.hpp"
#include "guaranteed_state_store.hpp"
#include "pg/pg_pool.hpp"
#include "test_route_sink.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own GuaranteedStateStore against a clone of this schema
// (ADR-0038 migration).
yuzu::test::PgTestTemplate guardian_pg_tpl{"guardianstate", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    GuaranteedStateStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("guardianstate template: store failed to migrate");
}};

} // namespace

TEST_CASE("device lenses: Read-gated + audited on open", "[pg][device][routes]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    bool allow_read = true;
    // The lenses gate per-device via scoped_perm; Read toggled by allow_read.
    auto scoped_perm = [&allow_read](const httplib::Request&, httplib::Response& res,
                                     const std::string&, const std::string& op, const std::string&) {
        if (op == "Read" && !allow_read) { res.status = 403; return false; }
        return true;
    };
    std::vector<std::string> audited;
    bool audit_ok = true;      // flip to simulate a dropped evidence row (#1647)
    bool audit_throws = false; // flip to simulate a bad_alloc-class throw from audit_fn (#1647)
    auto audit = [&](const httplib::Request&, const std::string& a, const std::string&,
                     const std::string&, const std::string& tid, const std::string&) -> bool {
        audited.push_back(a + "|" + tid);
        // DeviceLensRoutes::AuditFn is bool-returning (#1549).
        if (audit_throws)
            throw std::runtime_error("audit DB write blew up");
        return audit_ok;
    };
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, scoped_perm, &store, audit);

    SECTION("Read denied -> 403, nothing rendered, no audit") {
        allow_read = false;
        auto dex = sink.Get("/fragments/device/dex?id=a-1");
        REQUIRE(dex);
        CHECK(dex->status == 403);
        auto gd = sink.Get("/fragments/device/guardian?id=a-1");
        REQUIRE(gd);
        CHECK(gd->status == 403);
        CHECK(audited.empty());
    }
    SECTION("Read allowed -> audited on open with the right verb") {
        allow_read = true;
        sink.Get("/fragments/device/dex?id=a-1");
        sink.Get("/fragments/device/guardian?id=a-1");
        bool saw_dex = false, saw_guardian = false;
        for (const auto& a : audited) {
            if (a == "dex.device.view|a-1") saw_dex = true;
            if (a == "guardian.device.view|a-1") saw_guardian = true;
        }
        CHECK(saw_dex);
        CHECK(saw_guardian);
    }
    // #1647: a per-device behavioural-PII lens whose audit row silently fails to
    // persist must surface the gap (Sec-Audit-Failed) — but as an HTML dashboard
    // surface it SET-AND-PROCEEDS (a transient audit hiccup must not blank the
    // operator's lens, unlike the strict REST per-device endpoints that fail closed).
    SECTION("audit-persist failure -> Sec-Audit-Failed header, fragment still renders") {
        allow_read = true;
        audit_ok = false; // the evidence row cannot persist
        auto dex = sink.Get("/fragments/device/dex?id=a-1");
        REQUIRE(dex);
        CHECK(dex->status == 200); // set-and-proceed
        CHECK(dex->get_header_value("Sec-Audit-Failed") == "true");
        auto gd = sink.Get("/fragments/device/guardian?id=a-1");
        REQUIRE(gd);
        CHECK(gd->status == 200);
        CHECK(gd->get_header_value("Sec-Audit-Failed") == "true");
    }
    // #1647 item 1: a bad_alloc-class throw out of audit_fn was previously silent
    // (no try/catch). The shared helper catches it, logs, flags the header, and the
    // handler still returns a response instead of letting the throw escape.
    SECTION("a throwing audit_fn is caught + flagged, never escapes the handler") {
        allow_read = true;
        audit_throws = true;
        auto dex = sink.Get("/fragments/device/dex?id=a-1");
        REQUIRE(dex);
        CHECK(dex->status == 200);
        CHECK(dex->get_header_value("Sec-Audit-Failed") == "true");
        auto gd = sink.Get("/fragments/device/guardian?id=a-1");
        REQUIRE(gd);
        CHECK(gd->status == 200);
        CHECK(gd->get_header_value("Sec-Audit-Failed") == "true");
    }
}

// SCOPE-ESCAPE regression (governance Gate-2/4 BLOCKING; both adversarial reviewers
// found it independently) — the DEX-lens leg. See test_device_routes.cpp's sibling
// "out-of-scope device is not listed/openable/live-queryable" for the
// list/page/live-dispatch legs of the same regression.
TEST_CASE("device lenses: out-of-scope DEX lens is 403, no PII read (not audited)",
          "[pg][device][routes][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, guardian_pg_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GuaranteedStateStore store(pool);
    auto scoped_perm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                          const std::string&, const std::string& agent_id) {
        if (agent_id == "other-team") { res.status = 403; return false; }
        return true;
    };
    std::vector<std::string> audited;
    auto audit = [&audited](const httplib::Request&, const std::string& a, const std::string&,
                            const std::string&, const std::string& tid,
                            const std::string&) -> bool {
        audited.push_back(a + "|" + tid);
        return true;
    };
    yuzu::server::test::TestRouteSink sink;
    DeviceLensRoutes routes;
    routes.register_routes(sink, scoped_perm, &store, audit);

    auto r = sink.Get("/fragments/device/dex?id=other-team");
    REQUIRE(r);
    CHECK(r->status == 403);
    CHECK(audited.empty());
}

// bare=1 mounts the fragment as a lens inside the Hardware CI record, which
// already renders its own 7-tab bar — the fragment's OWN 3-chip bar
// (device_lens_tabs, "Device info"/"DEX"/"Guardian") must not double up.
// store=nullptr routes both lenses through render_device_lens_placeholder,
// which still threads `tabs` the same way the real DEX/Guardian bodies do.
TEST_CASE("device lenses: bare=1 hides the lens tab bar", "[device][routes]") {
    auto okScoped = [](const httplib::Request&, httplib::Response&, const std::string&,
                       const std::string&, const std::string&) { return true; };

    SECTION("dex fragment: bare=1 omits the tab bar; without it, the bar renders") {
        yuzu::server::test::TestRouteSink sink;
        DeviceLensRoutes routes;
        routes.register_routes(sink, okScoped, /*store=*/nullptr);
        auto bare = sink.Get("/fragments/device/dex?id=a-1&bare=1");
        REQUIRE(bare);
        CHECK(bare->body.find("Device info") == std::string::npos);
        auto full = sink.Get("/fragments/device/dex?id=a-1");
        REQUIRE(full);
        CHECK(full->body.find("Device info") != std::string::npos);
    }
    SECTION("guardian fragment: bare=1 omits the tab bar; without it, the bar renders") {
        yuzu::server::test::TestRouteSink sink;
        DeviceLensRoutes routes;
        routes.register_routes(sink, okScoped, /*store=*/nullptr);
        auto bare = sink.Get("/fragments/device/guardian?id=a-1&bare=1");
        REQUIRE(bare);
        CHECK(bare->body.find("Device info") == std::string::npos);
        auto full = sink.Get("/fragments/device/guardian?id=a-1");
        REQUIRE(full);
        CHECK(full->body.find("Device info") != std::string::npos);
    }
}
