// test_tar_module_stream.cpp — M1 of the $Module capture source
// (docs/tar-module-loads.md). Pins three things the rest of the ladder relies on:
//   1. EventRing<T> (refactored from ProcEventRing) carries ModuleEvent with the
//      SAME backpressure contract — push/drain/overflow-drop/zero-clamp;
//   2. the module action / signed-state warehouse tokens are the stable SQL
//      vocabulary the rollup SQL and dashboard filter on;
//   3. the $Module schema is registered and self-consistent — every tier
//      translates, is queryable, carries module_dir + signing, and has rollup SQL.

#include "tar_module_stream.hpp"
#include "tar_schema_registry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

using namespace yuzu::tar;

TEST_CASE("EventRing<ModuleEvent> buffers and drains in order", "[tar][module]") {
    ModuleEventRing ring(4);
    ModuleEvent a;
    a.module_name = "a.dll";
    a.pid = 1;
    ModuleEvent b;
    b.module_name = "b.dll";
    b.pid = 2;
    CHECK(ring.push(a));
    CHECK(ring.push(b));
    auto out = ring.drain();
    REQUIRE(out.size() == 2);
    CHECK(out[0].module_name == "a.dll");
    CHECK(out[1].module_name == "b.dll");
    CHECK(ring.drain().empty()); // drain emptied the buffer
}

TEST_CASE("EventRing<ModuleEvent> drops on overflow and counts the drops", "[tar][module]") {
    ModuleEventRing ring(2);
    CHECK(ring.push(ModuleEvent{}));
    CHECK(ring.push(ModuleEvent{}));
    CHECK_FALSE(ring.push(ModuleEvent{})); // full → dropped
    CHECK(ring.dropped() == 1);
}

TEST_CASE("EventRing<ModuleEvent> drop counter accumulates across drain cycles", "[tar][module]") {
    ModuleEventRing ring(2);
    CHECK(ring.push(ModuleEvent{}));
    CHECK(ring.push(ModuleEvent{}));
    CHECK_FALSE(ring.push(ModuleEvent{})); // dropped #1
    ring.drain();                          // empties the buffer, NOT the drop counter
    CHECK(ring.push(ModuleEvent{}));
    CHECK(ring.push(ModuleEvent{}));
    CHECK_FALSE(ring.push(ModuleEvent{})); // dropped #2
    CHECK(ring.dropped() == 2);
}

TEST_CASE("EventRing<ModuleEvent> clamps a zero capacity to one", "[tar][module]") {
    ModuleEventRing ring(0);
    CHECK(ring.capacity() == 1);
    CHECK(ring.push(ModuleEvent{}));
    CHECK_FALSE(ring.push(ModuleEvent{}));
}

TEST_CASE("module action/signed tokens are the stable warehouse vocabulary", "[tar][module]") {
    CHECK(module_action_token(ModuleAction::kLoaded) == "loaded");
    CHECK(module_action_token(ModuleAction::kUnloaded) == "unloaded");
    CHECK(module_action_token(ModuleAction::kSeed) == "seed");
    CHECK(module_action_token(ModuleAction::kBlocked) == "blocked");

    CHECK(module_signed_token(ModuleSignedState::kUnknown) == "unknown");
    CHECK(module_signed_token(ModuleSignedState::kSigned) == "signed");
    CHECK(module_signed_token(ModuleSignedState::kUnsigned) == "unsigned");
    CHECK(module_signed_token(ModuleSignedState::kInvalid) == "invalid");
    CHECK(module_signed_token(ModuleSignedState::kRevoked) == "revoked");
}

TEST_CASE("$Module schema is registered and queryable across all tiers", "[tar][module][schema]") {
    for (const auto* dn : {"$Module_Live", "$Module_Hourly", "$Module_Daily", "$Module_Monthly"}) {
        INFO("dollar=" << dn);
        auto real = translate_dollar_name(dn);
        REQUIRE(real.has_value());
        CHECK(is_queryable_table(*real));
    }
}

TEST_CASE("module_live carries the M1 columns including module_dir + signing",
          "[tar][module][schema]") {
    auto cols = columns_for_table("module_live");
    auto has = [&](const std::string& c) {
        return std::find(cols.begin(), cols.end(), c) != cols.end();
    };
    CHECK(has("module_name"));
    CHECK(has("module_dir")); // the deliberate divergence from names-only
    CHECK(has("signed_state"));
    CHECK(has("signer"));
    CHECK(has("is_kernel"));
}

TEST_CASE("$Module rollup SQL is defined for every aggregate tier", "[tar][module][schema]") {
    for (const auto* tier : {"hourly", "daily", "monthly"}) {
        INFO("tier=" << tier);
        auto sql = rollup_sql("module", tier);
        REQUIRE_FALSE(sql.empty());
        CHECK(sql.find("module_" + std::string(tier)) != std::string::npos);
        CHECK(sql.find("load_count") != std::string::npos);
    }
}

TEST_CASE("$Module hourly rollup counts the 'loaded' action token", "[tar][module][schema]") {
    // Tie the rollup SQL's literal action predicate to the C++ token vocabulary,
    // so renaming module_action_token(kLoaded) can't silently desync the count.
    auto sql = rollup_sql("module", "hourly");
    REQUIRE_FALSE(sql.empty());
    CHECK(sql.find(std::string{"action = '"} +
                   std::string{module_action_token(ModuleAction::kLoaded)} + "'") != std::string::npos);
}

TEST_CASE("module capture methods are pre-stageable while kPlanned", "[tar][module][schema]") {
    // The collectors are kPlanned in M1; accepted_capture_methods still returns
    // them so an operator can pre-stage `module_capture_method` before M2/M4/M6.
    auto methods = accepted_capture_methods("module");
    REQUIRE_FALSE(methods.empty());
    auto has = [&](const std::string& m) {
        return std::find(methods.begin(), methods.end(), m) != methods.end();
    };
    CHECK(has("etw"));
    CHECK(has("auditd"));
    CHECK(has("endpoint_security"));
}
