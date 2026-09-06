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
#include <nlohmann/json.hpp>

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

    // #4021: a file-change/file-hash-equals rule. FileGuard is Windows-only for
    // the MVP (start() no-ops elsewhere), so this never actually arms a running
    // guard off Windows — what IS testable everywhere is start_guard_for_rule_locked's
    // config-build step (path/expected_hash/baseline-seed), observed via
    // last_file_expected_hash_for_test(). `expected_hash` empty means author it
    // as baseline-on-arm (the case this issue is about).
    static gpb::GuaranteedStateRule make_file_hash_rule(const std::string& id,
                                                        const std::string& path,
                                                        const std::string& expected_hash = "") {
        gpb::GuaranteedStateRule r = make_rule(id, id);
        r.mutable_spark()->set_type("file-change");
        auto* a = r.mutable_assertion();
        a->set_type("file-hash-equals");
        (*a->mutable_params())["path"] = path;
        if (!expected_hash.empty())
            (*a->mutable_params())["expected_hash"] = expected_hash;
        return r;
    }

    static gpb::GuaranteedStatePush make_push(std::vector<gpb::GuaranteedStateRule> rules,
                                              bool full_sync) {
        gpb::GuaranteedStatePush push;
        push.set_full_sync(full_sync);
        for (auto& r : rules)
            *push.add_rules() = std::move(r);
        return push;
    }
};

} // namespace

// ── #4021: persisted baseline survives full_sync / seeds a re-arm ──────────
//
// full_sync (any unrelated fleet rule mutation, or an agent restart) used to tear
// down every guard and re-arm fresh, with no memory of a baseline a rule had
// already captured — a `file-hash-equals` rule authored with no `expected_hash`
// would silently re-capture "whatever's on disk right now" as its new baseline,
// laundering genuine drift into a false compliant with no remediation. These
// tests exercise the KV-persisted-baseline substrate + the seed-lookup that now
// runs at legacy arm time (start_guard_for_rule_locked) — the config-build step
// runs identically on every OS; only the running FileGuard itself is
// Windows-only, so last_file_expected_hash_for_test() is what's observable here.

TEST_CASE("a file-hash-equals rule with no persisted baseline arms with no seed",
          "[guardian][engine][baseline]") {
    GuardianFixture f;
    f.engine->apply_rules(GuardianFixture::make_push({GuardianFixture::make_file_hash_rule("r1", "/tmp/x")},
                                           /*full_sync=*/true));
    CHECK(f.engine->last_file_expected_hash_for_test().empty()); // first-ever arm: nothing to seed
}

TEST_CASE("a persisted baseline matching this rule's fingerprint seeds the arm",
          "[guardian][engine][baseline]") {
    GuardianFixture f;
    const std::string hash(64, 'a');
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = "file-hash-equals|/tmp/x";
    j["hash"] = hash;
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    f.engine->apply_rules(GuardianFixture::make_push({GuardianFixture::make_file_hash_rule("r1", "/tmp/x")},
                                           /*full_sync=*/true));
    CHECK(f.engine->last_file_expected_hash_for_test() == hash);
}

TEST_CASE("a persisted baseline for a DIFFERENT target does not seed (fingerprint mismatch)",
          "[guardian][engine][baseline]") {
    GuardianFixture f;
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = "file-hash-equals|/tmp/some-other-path";
    j["hash"] = std::string(64, 'b');
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    f.engine->apply_rules(GuardianFixture::make_push({GuardianFixture::make_file_hash_rule("r1", "/tmp/x")},
                                           /*full_sync=*/true));
    CHECK(f.engine->last_file_expected_hash_for_test().empty()); // genuinely different target
}

TEST_CASE("an authored expected_hash always wins over any persisted baseline",
          "[guardian][engine][baseline]") {
    GuardianFixture f;
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = "file-hash-equals|/tmp/x";
    j["hash"] = std::string(64, 'c');
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    const std::string authored(64, 'd');
    f.engine->apply_rules(GuardianFixture::make_push(
        {GuardianFixture::make_file_hash_rule("r1", "/tmp/x", authored)}, /*full_sync=*/true));
    CHECK(f.engine->last_file_expected_hash_for_test() == authored);
}

TEST_CASE("full_sync clears the prior rule set but PRESERVES a persisted baseline",
          "[guardian][engine][baseline][full_sync]") {
    GuardianFixture f;
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = "file-hash-equals|/tmp/x";
    j["hash"] = std::string(64, 'e');
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    // r1 must be a REAL pushed rule first (Gate 3 quality-engineer follow-up:
    // otherwise the closing CHECK_FALSE below is vacuously true regardless of
    // whether the scoped-delete fix works, since rule:r1 was never written in
    // the first place).
    f.engine->apply_rules(
        GuardianFixture::make_push({GuardianFixture::make_rule("r1", "r1")}, /*full_sync=*/true));
    REQUIRE(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r1"));

    // r1's baseline was captured BEFORE this push; the new full_sync push doesn't
    // even name r1 (an unrelated rule's fleet edit, mirroring #3990's amplifier) —
    // r1 is genuinely gone from this push, same as the server omitting a
    // disabled/out-of-scope rule (guardian_push_builder.cpp). The baseline record
    // must survive regardless: the agent cannot distinguish "r1 was deleted" from
    // "r1 is temporarily out of scope for this push", and sweeping on absence
    // would reintroduce this issue's exact laundering the next time r1 reappears.
    f.engine->apply_rules(
        GuardianFixture::make_push({GuardianFixture::make_rule("other", "other")}, /*full_sync=*/true));

    auto raw = f.kv->get(GuardianEngine::kv_namespace(), "baseline:r1");
    REQUIRE(raw.has_value());
    auto parsed = nlohmann::json::parse(*raw);
    CHECK(parsed.value("hash", std::string{}) == std::string(64, 'e'));

    // The rule cache itself IS cleared by full_sync, unaffected by this change —
    // only baseline: keys are exempted from the sweep.
    CHECK_FALSE(f.kv->exists(GuardianEngine::kv_namespace(), "rule:r1"));
}

TEST_CASE("a full_sync that DOES re-arm the baselined rule seeds it from the persisted "
          "record, not from current disk content",
          "[guardian][engine][baseline][full_sync]") {
    GuardianFixture f;
    const std::string original_hash(64, 'f');
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = "file-hash-equals|/tmp/x";
    j["hash"] = original_hash;
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    // Simulates the exact bug scenario: r1 was baselined at `original_hash` some
    // time ago (possibly now genuinely drifted on disk — this test doesn't need a
    // real file since FileGuard doesn't run off Windows); an UNRELATED fleet edit
    // now triggers a full_sync that also re-includes r1 unchanged.
    f.engine->apply_rules(GuardianFixture::make_push({GuardianFixture::make_file_hash_rule("r1", "/tmp/x")},
                                           /*full_sync=*/true));
    CHECK(f.engine->last_file_expected_hash_for_test() == original_hash);

    // The persisted record itself is unchanged — this arm attempt (whether or not
    // a real guard ever runs to re-confirm it) did not silently recapture.
    auto raw = f.kv->get(GuardianEngine::kv_namespace(), "baseline:r1");
    REQUIRE(raw.has_value());
    CHECK(nlohmann::json::parse(*raw).value("hash", std::string{}) == original_hash);
}

// ── guardian_persist_baseline's overwrite guard (adversarial-review K1/C2-1) ──
//
// A TRANSIENT seed-lookup failure (or, equivalently for this guard's purposes,
// any reason a capture fires despite a good record already being on file) must
// never let the resulting fresh capture overwrite that good record — on the
// happy path a matching well-formed record means guardian_seed_baseline would
// have seeded expected_hash and the capture branch would never fire at all, so
// reaching persist with a same-fingerprint record already present is only
// reachable via a failed seed lookup. Exercised directly via the
// `_for_test` forwarders since the real call site (FileGuard::Config::
// on_baseline) only fires from a Windows-only guard worker this platform's
// tests cannot run end-to-end.

TEST_CASE("persist refuses to overwrite an existing SAME-fingerprint baseline",
          "[guardian][engine][baseline][persist]") {
    GuardianFixture f;
    const std::string fp = "file-hash-equals|/tmp/x";
    const std::string good(64, 'a');
    const std::string drifted(64, 'b');
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = fp;
    j["hash"] = good;
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    // Simulates a fresh capture reaching persist despite a good record already
    // on file (the only reachable cause: the seed lookup that should have
    // prevented this capture in the first place failed transiently).
    yuzu::agent::guardian_persist_baseline_for_test(*f.kv, "r1", fp, drifted);

    auto raw = f.kv->get(GuardianEngine::kv_namespace(), "baseline:r1");
    REQUIRE(raw.has_value());
    CHECK(nlohmann::json::parse(*raw).value("hash", std::string{}) == good); // NOT overwritten
}

TEST_CASE("persist writes normally when no baseline exists yet",
          "[guardian][engine][baseline][persist]") {
    GuardianFixture f;
    const std::string fp = "file-hash-equals|/tmp/x";
    const std::string hash(64, 'c');

    yuzu::agent::guardian_persist_baseline_for_test(*f.kv, "r1", fp, hash);

    auto seeded = yuzu::agent::guardian_seed_baseline_for_test(*f.kv, "r1", fp);
    REQUIRE(seeded.has_value());
    CHECK(*seeded == hash);
}

TEST_CASE("persist writes normally for a genuine retarget (different fingerprint)",
          "[guardian][engine][baseline][persist]") {
    GuardianFixture f;
    nlohmann::json j;
    j["schema"] = 1;
    j["fingerprint"] = "file-hash-equals|/tmp/old-path";
    j["hash"] = std::string(64, 'd');
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    const std::string new_fp = "file-hash-equals|/tmp/new-path";
    const std::string new_hash(64, 'e');
    yuzu::agent::guardian_persist_baseline_for_test(*f.kv, "r1", new_fp, new_hash);

    auto seeded = yuzu::agent::guardian_seed_baseline_for_test(*f.kv, "r1", new_fp);
    REQUIRE(seeded.has_value());
    CHECK(*seeded == new_hash); // the retarget's own capture DID write
}

TEST_CASE("persist writes normally over a malformed existing record (self-heals)",
          "[guardian][engine][baseline][persist]") {
    GuardianFixture f;
    const std::string fp = "file-hash-equals|/tmp/x";
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", "not valid json"));

    const std::string hash(64, 'f');
    yuzu::agent::guardian_persist_baseline_for_test(*f.kv, "r1", fp, hash);

    auto seeded = yuzu::agent::guardian_seed_baseline_for_test(*f.kv, "r1", fp);
    REQUIRE(seeded.has_value());
    CHECK(*seeded == hash);
}

// ── schema-version mismatch (Gate 3 quality-engineer follow-up) ────────────
//
// Pins the exact scenario the 7451b67df fingerprint/schema-version-separation
// fix was written for: a record from a future/incompatible schema must be
// treated as Malformed (recapture/rewrite, self-heals), never silently
// matched as-is or misread as "a different target" — deleting the schema
// check in read_baseline_record should flip both of these red.

TEST_CASE("seed does not match a record with a mismatched schema version",
          "[guardian][engine][baseline][persist]") {
    GuardianFixture f;
    const std::string fp = "file-hash-equals|/tmp/x";
    nlohmann::json j;
    j["schema"] = 2; // future/incompatible - kBaselineSchemaVersion is 1
    j["fingerprint"] = fp;
    j["hash"] = std::string(64, 'a');
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    auto seeded = yuzu::agent::guardian_seed_baseline_for_test(*f.kv, "r1", fp);
    CHECK_FALSE(seeded.has_value()); // Malformed, not a false match
}

TEST_CASE("persist overwrites a record with a mismatched schema version",
          "[guardian][engine][baseline][persist]") {
    GuardianFixture f;
    const std::string fp = "file-hash-equals|/tmp/x";
    nlohmann::json j;
    j["schema"] = 2;
    j["fingerprint"] = fp; // matching fingerprint - only the schema differs
    j["hash"] = std::string(64, 'a');
    REQUIRE(f.kv->set(GuardianEngine::kv_namespace(), "baseline:r1", j.dump()));

    // A schema mismatch must be read as Malformed, NOT as a same-fingerprint
    // match — otherwise the persist-side overwrite guard would (wrongly)
    // refuse this write, permanently wedging the record at the old schema.
    const std::string mismatch_hash(64, 'b');
    yuzu::agent::guardian_persist_baseline_for_test(*f.kv, "r1", fp, mismatch_hash);

    auto seeded = yuzu::agent::guardian_seed_baseline_for_test(*f.kv, "r1", fp);
    REQUIRE(seeded.has_value());
    CHECK(*seeded == mismatch_hash); // the write landed, not refused
}

TEST_CASE("arming a file-hash-equals rule wires the on_baseline capture callback",
          "[guardian][engine][baseline]") {
    // Gate 3 quality-engineer follow-up: distinct from
    // last_file_expected_hash_for_test (which only proves the seed lookup
    // ran) - this proves the CAPTURE callback was actually attached, since a
    // seeded rule never re-enters the branch that would exercise it.
    GuardianFixture f;
    CHECK_FALSE(f.engine->last_file_on_baseline_wired_for_test()); // nothing armed yet
    f.engine->apply_rules(GuardianFixture::make_push({GuardianFixture::make_file_hash_rule("r1", "/tmp/x")},
                                                     /*full_sync=*/true));
    CHECK(f.engine->last_file_on_baseline_wired_for_test());
}

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

// ── rung 6: apply_rules must honor enabled() the same way start_local does ──
// Previously apply_rules called start_guard_for_rule_locked for EVERY pushed
// rule regardless of enabled() (unlike start_local, which already skipped
// disabled cached rules on restart), so a disabled rule still armed a guard,
// and pushing an already-armed rule as disabled never stopped it. These use
// make_service_rule because it is the one fixture that arms a REAL guard
// cross-platform (SystemdServiceGuard on Linux+systemd, ServiceGuard on
// Windows) without depending on the target unit/service existing (R5) - a
// SKIP mirrors the existing [statereader] "no reachable system bus" precedent
// for environments where arming genuinely cannot happen.
//
// Every push here goes through guardian_dispatch_push_bytes_for_test (byte-
// serialize then parse INSIDE the DLL) rather than calling apply_rules()
// directly on a proto built in the test EXE - the #501 rationale above
// (GuardianFixture::make_rule) applies to any rule carrying a params Map, and
// make_service_rule's assertion().params() is exactly that. Calling
// apply_rules() directly on such a rule hits the cross-image hash-seed split
// on Windows MSVC debug builds: the DLL-side find() can miss the EXE-side-
// inserted "service_name" entry, arming with an empty service name instead of
// "Spooler" (caught on DGRHP: [guardian][engine] Windows run, 2026-07-16).

TEST_CASE("GuardianEngine: apply_rules never arms a guard for a disabled rule",
          "[guardian][engine][enabled]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_service_rule("svc-disabled", "audit");
    p.mutable_rules(0)->set_enabled(false);
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    CHECK(f.engine->rule_count() == 1);       // still persisted...
    CHECK(f.engine->armed_guard_count() == 0); // ...but never armed
}

TEST_CASE("GuardianEngine: full_sync does not arm a disabled rule alongside an enabled one",
          "[guardian][engine][enabled][full_sync]") {
    GuardianFixture f;
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_service_rule("svc-on", "audit");
    *p.add_rules() = GuardianFixture::make_service_rule("svc-off", "audit");
    p.mutable_rules(1)->set_enabled(false);
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    if (f.engine->armed_guard_count() == 0)
        SKIP("no reachable system bus in this environment");
    CHECK(f.engine->rule_count() == 2);
    CHECK(f.engine->armed_guard_count() == 1); // only svc-on
}

TEST_CASE("GuardianEngine: disabling a previously-armed rule stops it; re-enabling re-arms it",
          "[guardian][engine][enabled]") {
    GuardianFixture f;
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = GuardianFixture::make_service_rule("svc-toggle", "audit");
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    if (f.engine->armed_guard_count() == 0)
        SKIP("no reachable system bus in this environment");
    CHECK(f.engine->armed_guard_count() == 1);

    {
        gpb::GuaranteedStatePush p; // delta push: same rule_id, now disabled
        p.set_full_sync(false);
        *p.add_rules() = GuardianFixture::make_service_rule("svc-toggle", "audit");
        p.mutable_rules(0)->set_enabled(false);
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    CHECK(f.engine->rule_count() == 1);       // the rule is still tracked (disabled, not deleted)...
    CHECK(f.engine->armed_guard_count() == 0); // ...but its guard was stopped

    {
        gpb::GuaranteedStatePush p; // delta push: same rule_id, re-enabled
        p.set_full_sync(false);
        *p.add_rules() = GuardianFixture::make_service_rule("svc-toggle", "audit");
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    CHECK(f.engine->armed_guard_count() == 1); // re-armed
}

TEST_CASE("GuardianEngine: re-pushing an enabled rule with the same id replaces its guard, "
          "never double-arms",
          "[guardian][engine][enabled]") {
    GuardianFixture f;
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = GuardianFixture::make_service_rule("svc-replace", "audit");
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    if (f.engine->armed_guard_count() == 0)
        SKIP("no reachable system bus in this environment");
    CHECK(f.engine->armed_guard_count() == 1);

    {
        gpb::GuaranteedStatePush p; // delta push: same id, changed content, still enabled
        p.set_full_sync(false);
        *p.add_rules() = GuardianFixture::make_service_rule("svc-replace", "enforce");
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    CHECK(f.engine->rule_count() == 1);
    CHECK(f.engine->armed_guard_count() == 1); // swapped, not accumulated to 2
}

TEST_CASE("GuardianEngine: a same-id replacement with an invalid new assertion retires the prior "
          "guard instead of leaving it enforcing stale policy",
          "[guardian][engine][enabled]") {
    // Regression for a bug found reviewing the enabled()/replace contract:
    // start_guard_for_rule_locked's per-branch "stop the existing guard for this
    // rule_id" step ran only on the happy path, AFTER validating the new rule's
    // assertion type - so a same-id re-push whose new assertion failed validation
    // returned false early and left the PRIOR guard armed, silently enforcing a
    // stale definition even though apply_rules had already persisted (and reported
    // success for) the new one. The retire-existing-guard step is now hoisted to
    // the top of start_guard_for_rule_locked so every return path starts clean.
    GuardianFixture f;
    {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = GuardianFixture::make_service_rule("svc-invalidate", "audit");
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    if (f.engine->armed_guard_count() == 0)
        SKIP("no reachable system bus in this environment");
    CHECK(f.engine->armed_guard_count() == 1);

    {
        gpb::GuaranteedStatePush p; // delta push: same id, still enabled, INVALID assertion type
        p.set_full_sync(false);
        auto rule = GuardianFixture::make_service_rule("svc-invalidate", "audit");
        rule.mutable_assertion()->set_type("service-frobnicate"); // not a recognized assertion kind
        *p.add_rules() = rule;
        // persistence succeeds regardless of arm outcome
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
    CHECK(f.engine->rule_count() == 1);       // still persisted (as the new, invalid definition)...
    CHECK(f.engine->armed_guard_count() == 0); // ...but the OLD guard was retired, not left running
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
    CHECK(applied.error() == "guardian engine stopped");
}

TEST_CASE("GuardianEngine: stop() is sticky - a later start_local() does not resurrect the engine",
          "[guardian][engine][lifecycle]") {
    // rung 7.7a reordered start_local() to run AFTER SparkEngine start + wire_spark_engine.
    // If a stop() lands during boot (a SIGTERM / service-stop mid-startup), the later
    // start_local() must NOT bring the engine back to life - otherwise stop() was not
    // truthful (and at rung 7.7b, detection + buffered sends could resume post-stop).
    GuardianFixture f;
    f.engine->stop();
    // start_local() returns cleanly but is a no-op: it must not clear the stopped state.
    REQUIRE(f.engine->start_local().has_value());
    // Proof the engine stayed stopped: apply_rules still fails with "stopped". Without
    // the sticky guard, start_local() would have set stopped_=false and this would
    // succeed - i.e. the engine would have silently resurrected after stop() returned.
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = GuardianFixture::make_rule("r-1", "after-stop-then-startlocal");
    auto applied = f.engine->apply_rules(p);
    CHECK_FALSE(applied.has_value());
    CHECK(applied.error() == "guardian engine stopped");
}
