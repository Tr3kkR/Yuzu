/**
 * test_mfa_store.cpp — AuthDB MFA / TOTP method tests.
 *
 * Drives AuthDB::mfa_init_enrollment / mfa_verify_enrollment /
 * mfa_verify_login_code / mfa_consume_recovery_code /
 * mfa_regenerate_recovery_codes / mfa_disable / mfa_status against a
 * per-test temp auth.db with a fresh schema. Verifies:
 *   - status reads on never-enrolled, provisional, and enrolled rows
 *   - init/verify round-trip
 *   - replay protection on login codes
 *   - recovery codes are single-use and case-insensitive
 *   - regenerate wipes prior codes
 *   - disable clears the secret + recovery codes
 *   - re-enroll after disable succeeds
 */

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "../../../server/core/src/totp.hpp"
#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <memory>

using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;

namespace {

struct MfaFixture {
    std::filesystem::path data_dir;
    std::unique_ptr<AuthDB> db;

    MfaFixture() {
        // Construct AuthDB with cleanup_interval_secs=0 so the background
        // reaper jthread is not spawned. Catch2 instantiates this fixture
        // once per TEST_CASE_METHOD; with the production 60 s cadence the
        // jthread is spawned + joined ~100 times in a single test process,
        // which triggers a non-deterministic macOS-arm64 SIGSEGV (Linux
        // gcc-13 and Windows MSVC are unaffected). Diagnosed in PR #1199
        // via env-var experiment, then promoted to this constructor
        // parameter so production behaviour is untouched.
        data_dir = yuzu::test::unique_temp_path("yuzu-mfa-");
        std::filesystem::create_directories(data_dir);
        db = std::make_unique<AuthDB>(data_dir, /*cleanup_interval_secs=*/0);
        REQUIRE(db->initialize().has_value());

        // Seed a user — mfa_* methods key by username and require an
        // is_active row to exist.
        auto salt = AuthManager::random_bytes(16);
        auto salt_hex = AuthManager::bytes_to_hex(salt);
        auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
        REQUIRE(db->upsert_user("alice", hash, salt_hex, Role::admin).has_value());
    }

    ~MfaFixture() {
        db.reset();
        std::error_code ec;
        std::filesystem::remove_all(data_dir, ec);
    }

    /// Decode the base32 secret from the enrollment-init result and emit a
    /// TOTP code for the current step. Used to drive verify() with a code
    /// the production verifier will accept.
    std::string code_for_now(const std::string& secret_b32) {
        auto bytes = mfa::base32_decode(secret_b32);
        REQUIRE(bytes.has_value());
        std::string raw(reinterpret_cast<const char*>(bytes->data()), bytes->size());
        auto counter = mfa::current_counter(std::chrono::system_clock::now());
        return mfa::generate(raw, counter);
    }
};

} // namespace

TEST_CASE_METHOD(MfaFixture, "mfa_status on never-enrolled user", "[mfa][store]") {
    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE_FALSE(s->enrolled);
    REQUIRE(s->enrolled_at.empty());
    REQUIRE(s->disabled_at.empty());
    REQUIRE(s->recovery_codes_remaining == 0);
}

TEST_CASE_METHOD(MfaFixture, "mfa_init_enrollment provides URI and secret", "[mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());
    REQUIRE_FALSE(init->secret_base32.empty());
    REQUIRE(init->otpauth_uri.starts_with("otpauth://totp/Yuzu:alice"));
    REQUIRE(init->otpauth_uri.find("secret=" + init->secret_base32) != std::string::npos);

    // Still "not enrolled" — provisional rows do not stamp mfa_enrolled_at.
    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE_FALSE(s->enrolled);
}

TEST_CASE_METHOD(MfaFixture, "mfa_verify_enrollment with valid code enrolls and issues codes",
                 "[mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);

    auto recovery = db->mfa_verify_enrollment("alice", code);
    REQUIRE(recovery.has_value());
    REQUIRE(recovery->size() == 10);

    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE(s->enrolled);
    REQUIRE(s->recovery_codes_remaining == 10);
}

TEST_CASE_METHOD(MfaFixture, "mfa_verify_enrollment rejects wrong code", "[mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());

    auto r = db->mfa_verify_enrollment("alice", "000000");
    REQUIRE_FALSE(r.has_value());
    REQUIRE(r.error() == AuthDBError::InvalidCredentials);

    auto s = db->mfa_status("alice");
    REQUIRE_FALSE(s->enrolled); // still provisional
}

TEST_CASE_METHOD(MfaFixture, "double init reuses provisional slot", "[mfa][store]") {
    auto first = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(first.has_value());
    auto second = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(second.has_value());
    // Secret rotated.
    REQUIRE(first->secret_base32 != second->secret_base32);
}

TEST_CASE_METHOD(MfaFixture, "init refuses if already enrolled", "[mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code).has_value());

    auto reinit = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE_FALSE(reinit.has_value());
    REQUIRE(reinit.error() == AuthDBError::MfaAlreadyEnrolled);
}

TEST_CASE_METHOD(MfaFixture, "mfa_verify_login_code replay-protected", "[mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code).has_value());

    // Same code in the same step is rejected on login (replay).
    auto replay = db->mfa_verify_login_code("alice", code);
    REQUIRE(replay.has_value());
    REQUIRE_FALSE(*replay);
}

TEST_CASE_METHOD(MfaFixture, "mfa_verify_login_code rejects garbage", "[mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code).has_value());

    auto r = db->mfa_verify_login_code("alice", "");
    REQUIRE(r.has_value());
    REQUIRE_FALSE(*r);

    auto r2 = db->mfa_verify_login_code("alice", "abcdef");
    REQUIRE(r2.has_value());
    REQUIRE_FALSE(*r2);
}

TEST_CASE_METHOD(MfaFixture, "recovery codes are single-use", "[mfa][store][recovery]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(init.has_value());
    auto code = code_for_now(init->secret_base32);
    auto recovery_res = db->mfa_verify_enrollment("alice", code);
    REQUIRE(recovery_res.has_value());

    const auto& codes = *recovery_res;
    REQUIRE_FALSE(codes.empty());

    auto first = db->mfa_consume_recovery_code("alice", codes.front());
    REQUIRE(first.has_value());
    REQUIRE(*first);

    auto replay = db->mfa_consume_recovery_code("alice", codes.front());
    REQUIRE(replay.has_value());
    REQUIRE_FALSE(*replay);

    auto s = db->mfa_status("alice");
    REQUIRE(s->recovery_codes_remaining == 9);
}

TEST_CASE_METHOD(MfaFixture, "recovery codes normalise separator and case",
                 "[mfa][store][recovery]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    auto code = code_for_now(init->secret_base32);
    auto recovery_res = db->mfa_verify_enrollment("alice", code);
    REQUIRE(recovery_res.has_value());
    auto orig = recovery_res->front(); // shape "XXXXX-XXXXX"

    // Strip the dash; should still match the same stored row.
    std::string no_dash;
    for (char c : orig)
        if (c != '-')
            no_dash += c;

    auto stripped = db->mfa_consume_recovery_code("alice", no_dash);
    REQUIRE(stripped.has_value());
    REQUIRE(*stripped);

    // Lowercased should also have matched if we hadn't already consumed.
    auto next = recovery_res->at(1);
    std::string lower;
    for (char c : next)
        lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    auto matched = db->mfa_consume_recovery_code("alice", lower);
    REQUIRE(matched.has_value());
    REQUIRE(*matched);
}

TEST_CASE_METHOD(MfaFixture, "regenerate replaces all codes", "[mfa][store][recovery]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    auto code = code_for_now(init->secret_base32);
    auto first_set = db->mfa_verify_enrollment("alice", code);
    REQUIRE(first_set.has_value());

    auto second_set = db->mfa_regenerate_recovery_codes("alice");
    REQUIRE(second_set.has_value());
    REQUIRE(second_set->size() == 10);

    // Old codes no longer valid.
    auto stale = db->mfa_consume_recovery_code("alice", first_set->front());
    REQUIRE(stale.has_value());
    REQUIRE_FALSE(*stale);

    // New ones are.
    auto fresh = db->mfa_consume_recovery_code("alice", second_set->front());
    REQUIRE(fresh.has_value());
    REQUIRE(*fresh);
}

TEST_CASE_METHOD(MfaFixture, "disable clears secret and recovery codes", "[mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code).has_value());

    REQUIRE(db->mfa_disable("alice").has_value());

    auto s = db->mfa_status("alice");
    REQUIRE(s.has_value());
    REQUIRE_FALSE(s->enrolled);
    REQUIRE_FALSE(s->disabled_at.empty());
    REQUIRE(s->recovery_codes_remaining == 0);

    // Re-init works after disable.
    auto reinit = db->mfa_init_enrollment("alice", "Yuzu");
    REQUIRE(reinit.has_value());
}

TEST_CASE_METHOD(MfaFixture, "verify_login_code on disabled user always fails", "[mfa][store]") {
    auto init = db->mfa_init_enrollment("alice", "Yuzu");
    auto code = code_for_now(init->secret_base32);
    REQUIRE(db->mfa_verify_enrollment("alice", code).has_value());
    REQUIRE(db->mfa_disable("alice").has_value());

    auto r = db->mfa_verify_login_code("alice", code);
    REQUIRE(r.has_value());
    REQUIRE_FALSE(*r);
}
