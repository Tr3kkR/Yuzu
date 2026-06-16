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

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>

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

// Path uniqueness delegates to the shared salt + atomic counter helper in
// test_helpers.hpp — the pattern a90a21e introduced for this file is now the
// single source of truth for every test harness. See #482 for history.
fs::path unique_kv_path() {
    const auto dir = fs::temp_directory_path() / ("yuzu_test_guardian" + uid_suffix());
    return dir / (yuzu::test::unique_temp_path("guardian_").filename().string() + ".db");
}

struct GuardianFixture {
    // FIRST member — destructor fires even if downstream construction
    // throws, so a partial REQUIRE failure below does not leak the .db /
    // -wal / -shm trio. RAII cleanup means no manual fs::remove here.
    yuzu::test::TempDbFile db_{unique_kv_path()};
    std::unique_ptr<KvStore> kv;
    std::unique_ptr<GuardianEngine> engine;

    GuardianFixture() {
        auto opened = KvStore::open(db_.path);
        REQUIRE(opened.has_value());
        kv = std::make_unique<KvStore>(std::move(*opened));
        engine = std::make_unique<GuardianEngine>(kv.get(), "agent-test");
        REQUIRE(engine->start_local().has_value());
    }

    // Default destructor: engine → kv → db_ destroy in reverse-declaration
    // order, so SQLite handles close before TempDbFile removes the files.

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

    // A rule that actually arms a RegistryGuard on Windows (registry-change spark
    // + registry-value-equals assertion). The key need not exist — post-C1 the
    // guard worker stays ALIVE on a nearest-ancestor watch (waiting for the key to
    // appear) instead of exiting; get_status is still fail-closed because there is
    // no self-test verdict yet, so the rule reports "errored" regardless.
    static gpb::GuaranteedStateRule make_registry_rule(const std::string& id,
                                                       const std::string& mode) {
        gpb::GuaranteedStateRule r = make_rule(id, id);
        r.set_enforcement_mode(mode);
        r.mutable_spark()->set_type("registry-change");
        auto* a = r.mutable_assertion();
        a->set_type("registry-value-equals");
        (*a->mutable_params())["hive"] = "HKCU";
        (*a->mutable_params())["key"] = "SOFTWARE\\YuzuTest\\GuardStatusTest";
        (*a->mutable_params())["value_name"] = "Flag";
        (*a->mutable_params())["value_type"] = "REG_DWORD";
        (*a->mutable_params())["expected"] = "1";
        return r;
    }

    // A rule that arms a service guard (service-status-change spark +
    // service-running assertion): ServiceGuard on Windows, SystemdServiceGuard on
    // Linux+systemd, no-op elsewhere. The service/unit need not exist — the guard
    // watches for it; get_status is fail-closed regardless (no self-test verdict yet).
    static gpb::GuaranteedStateRule make_service_rule(const std::string& id,
                                                      const std::string& mode) {
        gpb::GuaranteedStateRule r = make_rule(id, id);
        r.set_enforcement_mode(mode);
        r.mutable_spark()->set_type("service-status-change");
        auto* a = r.mutable_assertion();
        a->set_type("service-running");
        (*a->mutable_params())["service_name"] = "Spooler";
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

    // Route through the DLL-side helper: building the CommandRequest and
    // populating its `parameters` map must happen inside yuzu_agent_core
    // so that the dispatch-time find() uses the same absl::HashOf seed as
    // the insert(). See guardian_engine.hpp and #501 for the full story.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(
        *f.engine, p.SerializeAsString());
    CHECK(dr.exit_code == 0);
    CHECK(dr.content_type == "text");
    // Space-anchor the numeric substrings: the raw output is
    // "applied=1 generation=42 total=1" and a bare `"applied=1"` search would
    // also match `"applied=10"` / `"applied=100"` if this test ever grows.
    CHECK(dr.output.find("applied=1 ") != std::string::npos);
    CHECK(dr.output.find(" generation=42 ") != std::string::npos);
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
    // Fail-closed: rules report errored, never compliant, without a real verdict.
    CHECK(status.errored_rules() == 2);
    CHECK(status.compliant_rules() == 0);
    CHECK(status.rules_size() == 2);
}

TEST_CASE("GuardianEngine: get_status is fail-closed — an armed guard is never healthy/compliant",
          "[guardian][engine][status][health]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    // audit (not enforce) so this status test never triggers C2's enforce-mode key
    // recreation as a side effect — it only needs an armed guard to assert
    // fail-closed status, which holds regardless of enforcement mode.
    *p.add_rules() = GuardianFixture::make_registry_rule("reg-1", "audit");
    // Serialize-then-dispatch so the params Map is parsed INSIDE the agent DLL
    // (the #501 cross-image hash-seed reason the helper exists). On Windows this
    // arms a real RegistryGuard (post-C1 its worker stays alive on a nearest-
    // ancestor watch while the key is absent); off-Windows no guard arms. Either
    // way the status MUST be fail-closed.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    auto status = f.engine->get_status();
    REQUIRE(status.rules_size() == 1);
    // The B1/UP-1/F4 false-green fix: armed (or dead-but-armed) does NOT prove
    // compliance or health. guard_healthy is a reserved field, default false.
    CHECK_FALSE(status.rules(0).guard_healthy());
    CHECK(status.rules(0).status() == "errored");
    CHECK(status.compliant_rules() == 0);
    CHECK(status.errored_rules() == 1);
}

TEST_CASE("GuardianEngine: a service-status-change rule dispatches and is fail-closed",
          "[guardian][engine][service][status]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    // audit mode: on Windows this arms a real ServiceGuard watching the SCM, on
    // Linux+systemd a SystemdServiceGuard watching the unit over sd-bus, no guard
    // off both. Either way the rule is persisted and status is fail-closed (no
    // self-test verdict yet → "errored", never healthy/compliant) — the same
    // B1/UP-1/F4 invariant as the registry case.
    *p.add_rules() = GuardianFixture::make_service_rule("svc-1", "audit");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    auto status = f.engine->get_status();
    REQUIRE(status.rules_size() == 1);
    CHECK_FALSE(status.rules(0).guard_healthy());
    CHECK(status.rules(0).status() == "errored");
    CHECK(status.compliant_rules() == 0);
    CHECK(status.errored_rules() == 1);
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

TEST_CASE("GuardianEngine: dispatch push_rules with missing payload → exit_code 1",
          "[guardian][engine][dispatch][error]") {
    GuardianFixture f;
    apb::CommandRequest cmd;
    cmd.set_plugin("__guard__");
    cmd.set_action("push_rules");
    auto dr = f.engine->dispatch(cmd);
    CHECK(dr.exit_code == 1);
    // The push rides in the `payload` bytes field (not a `parameters` entry)
    // since the payload-bytes migration; an empty payload reports accordingly.
    CHECK(dr.output.find("missing payload") != std::string::npos);
}

TEST_CASE("GuardianEngine: dispatch push_rules with garbage proto → exit_code 2",
          "[guardian][engine][dispatch][error]") {
    GuardianFixture f;
    // Same DLL-boundary reasoning as the success test above — see #501 and
    // guardian_engine.hpp for the absl hash seed cross-image mismatch.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(
        *f.engine, "not a valid proto byte sequence");
    CHECK(dr.exit_code == 2);
    CHECK(dr.output.find("failed to parse") != std::string::npos);
}

TEST_CASE("GuardianEngine: rule cache + policy_generation survive engine reconstruct",
          "[guardian][engine][persistence]") {
    yuzu::test::TempDbFile db{unique_kv_path()};
    {
        auto opened = KvStore::open(db.path);
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
        auto opened = KvStore::open(db.path);
        REQUIRE(opened.has_value());
        auto kv = std::make_unique<KvStore>(std::move(*opened));
        GuardianEngine eng(kv.get(), "agent-test");
        REQUIRE(eng.start_local().has_value());
        CHECK(eng.rule_count() == 1);
        CHECK(eng.policy_generation() == 13);
    }
    // db destructor removes .db / -wal / -shm on scope exit.
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

TEST_CASE("GuardianEngine: drift event_id embeds agent_id (#1307)",
          "[guardian][engine][event][event_id]") {
    GuardianFixture f;  // agent_id == "agent-test"

    std::string captured_id;
    f.engine->set_event_sink([&captured_id](const gpb::GuaranteedStateEvent& ev) {
        captured_id = ev.event_id();
    });

    yuzu::agent::GuardDrift d;
    d.guard_type = "registry";
    d.rule_id = "rule-A";
    d.rule_name = "rule-A";
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, d);

    REQUIRE_FALSE(captured_id.empty());
    // Layout is "<rule_id>-<agent_id>-<ms>-<seq>"; assert agent_id is present and
    // sits immediately after the rule_id prefix (the slot the crash path uses).
    CHECK(captured_id.find("agent-test") != std::string::npos);
    CHECK(captured_id.rfind("rule-A-agent-test-", 0) == 0);
}

TEST_CASE("GuardianEngine: same rule + same seq on two agents → distinct event_ids (#1307)",
          "[guardian][engine][event][event_id]") {
    // The fleet-collision regression: per-agent event_seq_ both start at 0, so two
    // agents drifting on the SAME rule in the SAME millisecond previously minted an
    // identical "rule_id-ms-0" id and the server's global-PK events table dropped
    // all but one. Folding agent_id in must make the ids distinct regardless of
    // timing — so this test does NOT depend on the two emits landing in the same ms.
    // Declaration order pins the destruction contract (reverse order): eng_b,
    // eng_a destruct (stop(), no KV touch) before kv_b, kv_a close their SQLite
    // handles, before the TempDbFiles remove the .db/-wal/-shm trio — same engine
    // → kv → db ordering GuardianFixture documents at its top.
    yuzu::test::TempDbFile db_a{unique_kv_path()};
    yuzu::test::TempDbFile db_b{unique_kv_path()};
    auto open_a = KvStore::open(db_a.path);
    auto open_b = KvStore::open(db_b.path);
    REQUIRE(open_a.has_value());
    REQUIRE(open_b.has_value());
    KvStore kv_a{std::move(*open_a)};
    KvStore kv_b{std::move(*open_b)};
    GuardianEngine eng_a{&kv_a, "agent-alpha"};
    GuardianEngine eng_b{&kv_b, "agent-bravo"};
    REQUIRE(eng_a.start_local().has_value());
    REQUIRE(eng_b.start_local().has_value());

    std::string id_a, id_b;
    eng_a.set_event_sink([&id_a](const gpb::GuaranteedStateEvent& ev) { id_a = ev.event_id(); });
    eng_b.set_event_sink([&id_b](const gpb::GuaranteedStateEvent& ev) { id_b = ev.event_id(); });

    yuzu::agent::GuardDrift d;
    d.guard_type = "registry";
    d.rule_id = "shared-rule";
    d.rule_name = "shared-rule";
    // Both engines emit their first event (seq 0) for the same rule_id.
    yuzu::agent::guardian_emit_drift_for_test(eng_a, d);
    yuzu::agent::guardian_emit_drift_for_test(eng_b, d);

    REQUIRE_FALSE(id_a.empty());
    REQUIRE_FALSE(id_b.empty());
    CHECK(id_a != id_b);  // no PK collision
    // Prefix-anchor each id independently (not just containment): this pins the
    // "{rule_id}-{agent_id}-..." layout so the test fails against the pre-fix
    // "{rule_id}-{ms}-{seq}" shape on its own, without depending on a timing
    // difference between the two emits or on the sibling test having run.
    CHECK(id_a.rfind("shared-rule-agent-alpha-", 0) == 0);
    CHECK(id_b.rfind("shared-rule-agent-bravo-", 0) == 0);
}

TEST_CASE("GuardianEngine: empty agent_id still yields a well-formed (if ambiguous) event_id",
          "[guardian][engine][event][event_id]") {
    // Edge bordering the #1307 invariant: agent_id is server-assigned at enrollment
    // so it is non-empty in production, but assert the degenerate empty case does not
    // crash and still produces the "{rule_id}-{agent_id}-{ms}-{seq}" skeleton with an
    // empty agent_id segment ("rule-Z--<ms>-<seq>"). Documents that an empty agent_id
    // re-opens the cross-agent collision for that (pathological) population — see the
    // UP-2 follow-up — rather than silently changing shape.
    yuzu::test::TempDbFile db{unique_kv_path()};
    auto opened = KvStore::open(db.path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    GuardianEngine eng{&kv, ""};
    REQUIRE(eng.start_local().has_value());

    std::string captured_id;
    eng.set_event_sink([&captured_id](const gpb::GuaranteedStateEvent& ev) {
        captured_id = ev.event_id();
    });

    yuzu::agent::GuardDrift d;
    d.guard_type = "registry";
    d.rule_id = "rule-Z";
    d.rule_name = "rule-Z";
    yuzu::agent::guardian_emit_drift_for_test(eng, d);

    REQUIRE_FALSE(captured_id.empty());
    CHECK(captured_id.rfind("rule-Z--", 0) == 0);  // empty agent_id segment, not a crash
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
