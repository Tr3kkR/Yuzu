/**
 * test_rest_audit_helper.cpp — direct unit coverage for the shared
 * behavioural-data audit helper in `rest_audit.hpp` (#1647).
 *
 * The helper is the single chokepoint every per-device / per-signal PII route
 * (REST, dashboard fragments, MCP) now routes through, so its contract is
 * pinned here in isolation — independent of any one route — to stop the
 * per-site copies from drifting again:
 *
 *   try_persist_audit:
 *     - null audit_fn  → true  (audit-off ≠ a persist failure)
 *     - audit → true   → true
 *     - audit → false  → false
 *     - audit throws   → false (caught; the throw arm was previously silent)
 *
 *   emit_behavioral_audit (HTTP wrapper): the above, plus the
 *   `Sec-Audit-Failed: true` response header IFF the persist failed.
 */

#include "rest_audit.hpp"

#include <catch2/catch_test_macros.hpp>

#include <functional>
#include <stdexcept>
#include <string>

namespace {

using AuditFn = std::function<bool(const httplib::Request&, const std::string&, const std::string&,
                                   const std::string&, const std::string&, const std::string&)>;

bool call_emit(const AuditFn& fn, httplib::Response& res) {
    httplib::Request req;
    return yuzu::server::detail::emit_behavioral_audit(fn, req, res, "dex.device.view", "success",
                                                       "Agent", "WS-1", "unit test");
}

} // namespace

TEST_CASE("rest_audit: null audit_fn serves and sets no header (audit-off)", "[rest][audit][helper]") {
    httplib::Response res;
    CHECK(call_emit(AuditFn{}, res) == true);
    CHECK(res.get_header_value("Sec-Audit-Failed").empty());
}

TEST_CASE("rest_audit: a persisted row serves and sets no header", "[rest][audit][helper]") {
    httplib::Response res;
    AuditFn ok = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) { return true; };
    CHECK(call_emit(ok, res) == true);
    CHECK(res.get_header_value("Sec-Audit-Failed").empty());
}

TEST_CASE("rest_audit: a dropped row returns false + sets Sec-Audit-Failed", "[rest][audit][helper]") {
    httplib::Response res;
    AuditFn dropped = [](const httplib::Request&, const std::string&, const std::string&,
                         const std::string&, const std::string&, const std::string&) {
        return false;
    };
    CHECK(call_emit(dropped, res) == false);
    CHECK(res.get_header_value("Sec-Audit-Failed") == "true");
}

TEST_CASE("rest_audit: a throwing audit_fn is caught → false + Sec-Audit-Failed",
          "[rest][audit][helper]") {
    httplib::Response res;
    AuditFn boom = [](const httplib::Request&, const std::string&, const std::string&,
                      const std::string&, const std::string&,
                      const std::string&) -> bool { throw std::runtime_error("audit DB blew up"); };
    // Must not propagate — the handler still gets a clean false, never a 500-by-throw.
    CHECK_NOTHROW(call_emit(boom, res));
    httplib::Response res2;
    CHECK(call_emit(boom, res2) == false);
    CHECK(res2.get_header_value("Sec-Audit-Failed") == "true");
}

TEST_CASE("rest_audit: try_persist_audit kernel mirrors the bool contract without a Response",
          "[rest][audit][helper]") {
    httplib::Request req;
    AuditFn ok = [](const httplib::Request&, const std::string&, const std::string&,
                    const std::string&, const std::string&, const std::string&) { return true; };
    AuditFn dropped = [](const httplib::Request&, const std::string&, const std::string&,
                         const std::string&, const std::string&, const std::string&) {
        return false;
    };
    CHECK(yuzu::server::detail::try_persist_audit(AuditFn{}, req, "a", "success", "Agent", "x",
                                                  "d") == true);
    CHECK(yuzu::server::detail::try_persist_audit(ok, req, "a", "success", "Agent", "x", "d") ==
          true);
    CHECK(yuzu::server::detail::try_persist_audit(dropped, req, "a", "success", "Agent", "x", "d") ==
          false);
}
