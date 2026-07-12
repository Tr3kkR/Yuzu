// principal_class presentation classifier (ADR-1005, execution-plan PR 1.2).
// Pins the closed value set {human, agent, none}, the machine-signal-wins
// precedence, and the anchored cookie-name match; "engine" must NOT be
// emittable until Phase 4 wires it.

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>

#include <httplib.h>

#include "principal_class.hpp"

using yuzu::server::principal_class_of;

namespace {
httplib::Request req_with(std::initializer_list<std::pair<std::string, std::string>> headers) {
    httplib::Request req;
    for (const auto& [k, v] : headers) req.headers.emplace(k, v);
    return req;
}
}  // namespace

TEST_CASE("bearer token classifies as agent", "[principal-class][adr1005]") {
    CHECK(principal_class_of(req_with({{"Authorization", "Bearer abc"}})) == "agent");
    CHECK(principal_class_of(req_with({{"X-Yuzu-Token", "abc"}})) == "agent");
}

TEST_CASE("session cookie classifies as human", "[principal-class][adr1005]") {
    CHECK(principal_class_of(req_with({{"Cookie", "yuzu_session=s1"}})) == "human");
    CHECK(principal_class_of(req_with({{"Cookie", "theme=dark; yuzu_session=s1"}})) == "human");
}

TEST_CASE("cookie-name match is anchored, not substring", "[principal-class][adr1005]") {
    CHECK(principal_class_of(req_with({{"Cookie", "not_yuzu_session=s1"}})) == "none");
    CHECK(principal_class_of(req_with({{"Cookie", "a=b; xyuzu_session=s1"}})) == "none");
    // A cookie VALUE containing the literal must not classify either.
    CHECK(principal_class_of(req_with({{"Cookie", "other=yuzu_session=x"}})) == "none");
}

TEST_CASE("no credential classifies as none", "[principal-class][adr1005]") {
    CHECK(principal_class_of(req_with({})) == "none");
    CHECK(principal_class_of(req_with({{"Cookie", "theme=dark"}})) == "none");
}

TEST_CASE("machine signal wins over ambient cookie", "[principal-class][adr1005]") {
    CHECK(principal_class_of(req_with({{"Cookie", "yuzu_session=s1"},
                                       {"Authorization", "Bearer abc"}})) == "agent");
}
