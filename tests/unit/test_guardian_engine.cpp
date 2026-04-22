/**
 * test_guardian_engine.cpp — Unit tests for GuardianEngine (Guardian PR 2).
 *
 * The engine accepts __guard__ commands (push_rules, get_status) over the
 * agent's CommandRequest dispatch path and persists rules into KvStore
 * under namespace "__guardian__". PR 2 has no real guard threads — these
 * tests verify the persistence + dispatch contract that PR 3 builds on.
 *
 * What is in scope:
 *   - apply_rules persists each rule under "rule:<id>" as binary-safe JSON
 *   - full_sync wipes the prior set; non-full_sync merges in
 *   - dispatch round-trips push_rules through proto SerializeAsString
 *   - dispatch returns a GuaranteedStateStatus on get_status
 *   - rule_count / policy_generation survive an in-process restart
 *     (re-construct GuardianEngine over the same KvStore)
 *   - kv-unavailable construction degrades gracefully without crashing
 *
 * What is out of scope (PR 3+):
 *   - Real guard threads, drift detection, remediation
 *   - sync_with_server doing anything beyond logging
 */

#include <yuzu/agent/guardian_engine.hpp>
#include <yuzu/agent/kv_store.hpp>

#include "agent.grpc.pb.h"
#include "guaranteed_state.pb.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace gpb = ::yuzu::guardian::v1;
namespace apb = ::yuzu::agent::v1;
using yuzu::agent::GuardianEngine;
using yuzu::agent::KvStore;

namespace {

std::string uid_suffix() {
#ifdef _WIN32
    if (const char* u = std::getenv("USERNAME")) return std::string("_") + u;
    return "_unknown";
#else
    return "_" + std::to_string(static_cast<unsigned long>(::geteuid()));
#endif
}

fs::path unique_kv_path() {
    return fs::temp_directory_path() / ("yuzu_test_guardian" + uid_suffix()) /
           ("guardian_" +
            std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id())) + "_" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".db");
}

struct GuardianFixture {
    fs::path kv_path;
    std::unique_ptr<KvStore> kv;
    std::unique_ptr<GuardianEngine> engine;

    GuardianFixture() : kv_path(unique_kv_path()) {
        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        kv = std::make_unique<KvStore>(std::move(*opened));
        engine = std::make_unique<GuardianEngine>(kv.get(), "agent-test");
        REQUIRE(engine->start_local().has_value());
    }

    ~GuardianFixture() {
        engine.reset();
        kv.reset();
        std::error_code ec;
        fs::remove(kv_path, ec);
        fs::remove(fs::path{kv_path.string() + "-wal"}, ec);
        fs::remove(fs::path{kv_path.string() + "-shm"}, ec);
    }

    static gpb::GuaranteedStateRule make_rule(const std::string& id, const std::string& name,
                                                bool enabled = true) {
        gpb::GuaranteedStateRule r;
        r.set_rule_id(id);
        r.set_name(name);
        r.set_yaml_source("name: " + name + "\n");
        r.set_version(1);
        r.set_enabled(enabled);
        r.set_enforcement_mode("enforce");
        return r;
    }
};

} // namespace

TEST_CASE("GuardianEngine: start_local on fresh KV reports zero rules",
          "[guardian][engine][start]") {
    GuardianFixture f;
    CHECK(f.engine->rule_count() == 0);
    CHECK(f.engine->policy_generation() == 0);
}

TEST_CASE("GuardianEngine: apply_rules persists rules and bumps generation",
          "[guardian][engine][apply]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush push;
    push.set_full_sync(true);
    push.set_policy_generation(7);
    *push.add_rules() = GuardianFixture::make_rule("r-1", "rule-one");
    *push.add_rules() = GuardianFixture::make_rule("r-2", "rule-two");

    auto applied = f.engine->apply_rules(push);
    REQUIRE(applied.has_value());
    CHECK(*applied == 2);
    CHECK(f.engine->rule_count() == 2);
    CHECK(f.engine->policy_generation() == 7);

    // Each rule landed under "rule:<id>" in the reserved KV namespace.
    auto keys = f.kv->list(GuardianEngine::kv_namespace(), "rule:");
    REQUIRE(keys.size() == 2);
    auto raw = f.kv->get(GuardianEngine::kv_namespace(), "rule:r-1");
    REQUIRE(raw.has_value());
    CHECK(raw->find("\"name\":\"rule-one\"") != std::string::npos);
}

TEST_CASE("GuardianEngine: full_sync replaces the prior rule set",
          "[guardian][engine][apply][full_sync]") {
    GuardianFixture f;
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = GuardianFixture::make_rule("r-1", "old-1");
        *p.add_rules() = GuardianFixture::make_rule("r-2", "old-2");
        REQUIRE(f.engine->apply_rules(p).has_value());
    }
    REQUIRE(f.engine->rule_count() == 2);

    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        p.set_policy_generation(99);
        *p.add_rules() = GuardianFixture::make_rule("r-99", "new-rule");
        REQUIRE(f.engine->apply_rules(p).has_value());
    }

    CHECK(f.engine->rule_count() == 1);
    CHECK(f.engine->policy_generation() == 99);
    CHECK_FALSE(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r-1"));
    CHECK(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r-99"));
}

TEST_CASE("GuardianEngine: delta merge keeps prior rules and updates overlap",
          "[guardian][engine][apply][delta]") {
    GuardianFixture f;
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = GuardianFixture::make_rule("r-1", "first");
        REQUIRE(f.engine->apply_rules(p).has_value());
    }
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(false);
        *p.add_rules() = GuardianFixture::make_rule("r-1", "first-renamed");
        *p.add_rules() = GuardianFixture::make_rule("r-2", "second");
        REQUIRE(f.engine->apply_rules(p).has_value());
    }
    CHECK(f.engine->rule_count() == 2);
    auto raw = f.kv->get(GuardianEngine::kv_namespace(), "rule:r-1");
    REQUIRE(raw.has_value());
    CHECK(raw->find("\"name\":\"first-renamed\"") != std::string::npos);
}

TEST_CASE("GuardianEngine: rules with empty rule_id are skipped, not persisted",
          "[guardian][engine][apply][validation]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_rule("", "no-id");
    *p.add_rules() = GuardianFixture::make_rule("r-keep", "valid");
    auto applied = f.engine->apply_rules(p);
    REQUIRE(applied.has_value());
    CHECK(*applied == 1);
    CHECK(f.engine->rule_count() == 1);
}

TEST_CASE("GuardianEngine: dispatch routes push_rules through SerializeAsString",
          "[guardian][engine][dispatch][push]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(42);
    *p.add_rules() = GuardianFixture::make_rule("r-d", "dispatched");

    apb::CommandRequest cmd;
    cmd.set_command_id("cmd-1");
    cmd.set_plugin("__guard__");
    cmd.set_action("push_rules");
    (*cmd.mutable_parameters())["push"] = p.SerializeAsString();

    auto dr = f.engine->dispatch(cmd);
    CHECK(dr.exit_code == 0);
    CHECK(dr.content_type == "text");
    CHECK(dr.output.find("applied=1") != std::string::npos);
    CHECK(dr.output.find("generation=42") != std::string::npos);
    CHECK(f.engine->rule_count() == 1);
    CHECK(f.engine->policy_generation() == 42);
}

TEST_CASE("GuardianEngine: dispatch get_status returns serialised proto",
          "[guardian][engine][dispatch][status]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_rule("r-1", "a");
    *p.add_rules() = GuardianFixture::make_rule("r-2", "b");
    REQUIRE(f.engine->apply_rules(p).has_value());

    apb::CommandRequest cmd;
    cmd.set_command_id("cmd-status");
    cmd.set_plugin("__guard__");
    cmd.set_action("get_status");

    auto dr = f.engine->dispatch(cmd);
    REQUIRE(dr.exit_code == 0);
    CHECK(dr.content_type == "proto");

    gpb::GuaranteedStateStatus status;
    REQUIRE(status.ParseFromString(dr.output));
    CHECK(status.agent_id() == "agent-test");
    CHECK(status.total_rules() == 2);
    // PR 2 reports every rule as errored — no real guards yet.
    CHECK(status.errored_rules() == 2);
    CHECK(status.compliant_rules() == 0);
    CHECK(status.rules_size() == 2);
}

TEST_CASE("GuardianEngine: dispatch unknown action fails with detail",
          "[guardian][engine][dispatch][error]") {
    GuardianFixture f;
    apb::CommandRequest cmd;
    cmd.set_plugin("__guard__");
    cmd.set_action("not_a_real_action");
    auto dr = f.engine->dispatch(cmd);
    CHECK(dr.exit_code != 0);
    CHECK(dr.output.find("not_a_real_action") != std::string::npos);
}

TEST_CASE("GuardianEngine: dispatch push_rules with missing param → exit_code 1",
          "[guardian][engine][dispatch][error]") {
    GuardianFixture f;
    apb::CommandRequest cmd;
    cmd.set_plugin("__guard__");
    cmd.set_action("push_rules");
    auto dr = f.engine->dispatch(cmd);
    CHECK(dr.exit_code == 1);
    CHECK(dr.output.find("missing 'push' parameter") != std::string::npos);
}

TEST_CASE("GuardianEngine: dispatch push_rules with garbage proto → exit_code 2",
          "[guardian][engine][dispatch][error]") {
    GuardianFixture f;
    apb::CommandRequest cmd;
    cmd.set_plugin("__guard__");
    cmd.set_action("push_rules");
    (*cmd.mutable_parameters())["push"] = "not a valid proto byte sequence";
    auto dr = f.engine->dispatch(cmd);
    CHECK(dr.exit_code == 2);
    CHECK(dr.output.find("failed to parse") != std::string::npos);
}

TEST_CASE("GuardianEngine: rule cache + policy_generation survive engine reconstruct",
          "[guardian][engine][persistence]") {
    auto kv_path = unique_kv_path();
    {
        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        auto kv = std::make_unique<KvStore>(std::move(*opened));
        GuardianEngine eng(kv.get(), "agent-test");
        REQUIRE(eng.start_local().has_value());

        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        p.set_policy_generation(13);
        *p.add_rules() = GuardianFixture::make_rule("r-x", "persisted");
        REQUIRE(eng.apply_rules(p).has_value());
    }
    // Re-open the same KV file under a fresh engine and verify recovery.
    {
        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        auto kv = std::make_unique<KvStore>(std::move(*opened));
        GuardianEngine eng(kv.get(), "agent-test");
        REQUIRE(eng.start_local().has_value());
        CHECK(eng.rule_count() == 1);
        CHECK(eng.policy_generation() == 13);
    }
    std::error_code ec;
    fs::remove(kv_path, ec);
    fs::remove(fs::path{kv_path.string() + "-wal"}, ec);
    fs::remove(fs::path{kv_path.string() + "-shm"}, ec);
}

TEST_CASE("GuardianEngine: construction with null KvStore degrades gracefully",
          "[guardian][engine][robustness]") {
    GuardianEngine eng(nullptr, "agent-test");
    REQUIRE(eng.start_local().has_value());  // soft success — warns and proceeds

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_rule("r-1", "no-kv");
    auto applied = eng.apply_rules(p);
    CHECK_FALSE(applied.has_value());
    CHECK(applied.error().find("kv store unavailable") != std::string::npos);
}

TEST_CASE("GuardianEngine: stop() makes subsequent apply_rules fail",
          "[guardian][engine][lifecycle]") {
    GuardianFixture f;
    f.engine->stop();

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_rule("r-1", "after-stop");
    auto applied = f.engine->apply_rules(p);
    CHECK_FALSE(applied.has_value());
    CHECK(applied.error().find("stopped") != std::string::npos);
}
