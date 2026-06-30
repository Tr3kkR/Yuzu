// Pure parse + validation layer for the /auto DEPLOY stage. Always runs (no PG):
// content_dist stage/execute output shapes → outcomes, artifact validation, and
// the step token vocabulary.

#include <catch2/catch_test_macros.hpp>

#include "deployment_parse.hpp"

using namespace yuzu::server::deployment;

TEST_CASE("parse_stage reads content_dist stage output", "[deployment][parse]") {
    SECTION("success: status|ok + staged_path") {
        auto r = parse_stage(1, "status|ok\nstaged_path|/var/yuzu/staged/pkg.msi");
        CHECK(r.outcome == PhaseOutcome::kOk);
        CHECK(r.error.empty());
    }
    SECTION("failure: error| line carries the message") {
        auto r = parse_stage(2, "error|hash mismatch: expected=ab, got=cd");
        CHECK(r.outcome == PhaseOutcome::kFailed);
        CHECK(r.error == "hash mismatch: expected=ab, got=cd");
    }
    SECTION("no terminal signal yet → pending") {
        CHECK(parse_stage(0, "").outcome == PhaseOutcome::kPending);
        CHECK(parse_stage(0, "progress|downloading").outcome == PhaseOutcome::kPending);
    }
    SECTION("terminal FAILURE status with no body → failed") {
        CHECK(parse_stage(2, "").outcome == PhaseOutcome::kFailed);
    }
}

TEST_CASE("parse_exec reads content_dist execute_staged output", "[deployment][parse]") {
    SECTION("success: status|ok + exit_code|0") {
        auto r = parse_exec(1, "status|ok\nexit_code|0\noutput|installed");
        CHECK(r.outcome == PhaseOutcome::kOk);
        CHECK(r.exit_code == 0);
    }
    SECTION("non-zero exit: status|error + exit_code") {
        auto r = parse_exec(2, "status|error\nexit_code|1603");
        CHECK(r.outcome == PhaseOutcome::kFailed);
        CHECK(r.exit_code == 1603);
    }
    SECTION("validation reject path: error| only, no status/exit") {
        auto r = parse_exec(2, "error|no trusted hash on record for staged file 'pkg.msi'");
        CHECK(r.outcome == PhaseOutcome::kFailed);
        CHECK(r.error.find("no trusted hash") != std::string::npos);
        CHECK(r.exit_code == 0);
    }
    SECTION("not terminal → pending") {
        CHECK(parse_exec(0, "").outcome == PhaseOutcome::kPending);
    }
}

TEST_CASE("config_valid enforces artifact constraints", "[deployment][parse]") {
    const std::string good_sha(64, 'a');
    DeploymentConfig ok{"https://repo.lan/pkg.msi", "pkg.msi", good_sha, "/qn /norestart"};
    std::string why;
    CHECK(config_valid(ok, &why));

    SECTION("bad url scheme") {
        DeploymentConfig c = ok;
        c.url = "ftp://repo/pkg.msi";
        CHECK_FALSE(config_valid(c, &why));
        CHECK(why.find("URL") != std::string::npos);
    }
    SECTION("filename with a path separator or .. is rejected") {
        DeploymentConfig c = ok;
        c.filename = "../evil.msi";
        CHECK_FALSE(config_valid(c));
        CHECK_FALSE(is_valid_filename("a/b"));
        CHECK_FALSE(is_valid_filename("a\\b"));
        CHECK_FALSE(is_valid_filename("..hidden.msi")); // ".." even without a separator
        CHECK(is_valid_filename("Pkg-4.2.0_x64.msi"));
    }
    SECTION("sha256 must be 64 hex") {
        DeploymentConfig c = ok;
        c.sha256 = "deadbeef"; // too short
        CHECK_FALSE(config_valid(c));
        CHECK_FALSE(is_valid_sha256(std::string(63, 'a')));
        CHECK_FALSE(is_valid_sha256(std::string(64, 'g'))); // non-hex
        CHECK(is_valid_sha256(std::string(64, 'A')));        // case-insensitive
    }
    SECTION("args reject shell metacharacters but allow real Windows paths") {
        DeploymentConfig c = ok;
        c.args = "/qn & calc.exe";
        CHECK_FALSE(config_valid(c, &why));
        CHECK(why.find("args") != std::string::npos);
        CHECK_FALSE(is_valid_args("/x $(whoami)")); // $ and ( ) blocked
        CHECK_FALSE(is_valid_args("a | b"));        // pipe blocked
        // not stricter than the agent: backslash / = : / space stay legal
        CHECK(is_valid_args("/D C:\\Program Files\\App /qn"));
        CHECK(is_valid_args("/log=C:\\temp\\install.log"));
        CHECK(is_valid_args("/qn /norestart"));
        CHECK(is_valid_args("")); // optional
    }
}

TEST_CASE("step tokens round-trip and terminality", "[deployment][parse]") {
    for (Step s : {Step::kPending, Step::kStaging, Step::kStaged, Step::kExecuting,
                   Step::kSucceeded, Step::kFailed, Step::kSkipped})
        CHECK(step_from_token(step_token(s)) == s);
    CHECK(step_from_token("nonsense") == Step::kSkipped); // unknown → terminal sink, never re-dispatched

    CHECK_FALSE(step_is_terminal(Step::kPending));
    CHECK_FALSE(step_is_terminal(Step::kStaging));
    CHECK_FALSE(step_is_terminal(Step::kStaged));
    CHECK_FALSE(step_is_terminal(Step::kExecuting));
    CHECK(step_is_terminal(Step::kSucceeded));
    CHECK(step_is_terminal(Step::kFailed));
    CHECK(step_is_terminal(Step::kSkipped));
}
