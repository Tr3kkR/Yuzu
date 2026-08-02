// Runtime-config secret redaction, and a tripwire against the next one.
//
// WHY THIS EXISTS
// ---------------
// `oidc_client_secret` is stored in runtime-config as plaintext (ADR-0010 envelope
// encryption for this store has not landed). That is a known, accepted at-rest
// position -- but the VALUE was also being emitted twice:
//
//   * written verbatim to yuzu-server.log on every boot by the startup override pass;
//   * returned by GET /api/config, which is gated only on Infrastructure:Read.
//
// Both contradicted the settings UI, which has always rendered the same field as
// "********". Redaction is now the emitter's job and `is_secret_key` is the single
// predicate every emitter consults.
//
// The tripwire below is the durable half. A future secret-valued key added to
// `allowed_keys()` and NOT to the secret list would silently start leaking through
// FOUR paths - the startup log, the GET /api/config override list, the PUT audit
// detail and the PUT response echo - and nothing else would notice. (This sentence
// said "the same two paths" while the fix was mid-flight; the audit detail and the
// response echo were found afterwards. A count in a comment is a fact that rots.)

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>
#include <algorithm>
#include <vector>

#include "runtime_config_store.hpp"
#include "../test_helpers.hpp"

using yuzu::server::RuntimeConfigStore;

TEST_CASE("is_secret_key identifies credential-valued keys", "[runtime_config][secret]") {
    CHECK(RuntimeConfigStore::is_secret_key("oidc_client_secret"));

    // Neighbouring OIDC keys are configuration, not credentials: redacting them would
    // cost an operator real diagnostic signal for no benefit.
    CHECK_FALSE(RuntimeConfigStore::is_secret_key("oidc_issuer"));
    CHECK_FALSE(RuntimeConfigStore::is_secret_key("oidc_client_id"));
    CHECK_FALSE(RuntimeConfigStore::is_secret_key("oidc_admin_group"));
    CHECK_FALSE(RuntimeConfigStore::is_secret_key("log_level"));

    // An unknown key is not a secret -- it is not storable at all.
    CHECK_FALSE(RuntimeConfigStore::is_secret_key("not_a_real_key"));
    CHECK_FALSE(RuntimeConfigStore::is_secret_key(""));
}

TEST_CASE("the redaction placeholder is a single fixed spelling", "[runtime_config][secret]") {
    // Log scrapers and API consumers must see one token, not a family of them.
    const std::string p = RuntimeConfigStore::redacted_placeholder();
    CHECK_FALSE(p.empty());
    // It must not be mistakable for a real value.
    CHECK(p.find('<') != std::string::npos);
}

TEST_CASE("TRIPWIRE: every credential-shaped allowed key is registered as secret",
          "[runtime_config][secret][tripwire]") {
    // If you are here because this failed, you added a key to `allowed_keys()` whose
    // NAME says it carries a credential. Either add it to `kSecretKeys` in
    // runtime_config_store.cpp so the log line and GET /api/config redact it, or --
    // if the name is misleading and the value is not a credential -- rename the key.
    // Do not relax this test to make it pass.
    //
    // Deliberately name-based: it cannot know a value is a credential, only that the
    // key is spelled like one. That catches the realistic mistake (a `*_secret` /
    // `*_password` / `*_token` key added without redaction) and is honest about what
    // it cannot catch -- a credential-valued key with an innocuous name, which needs a
    // human to notice.
    // NOT "_key" on its own: `dex_cohort_export_key` is an allowed key whose value is
    // a grouping mode ("model"), so that suffix is genuinely ambiguous here and would
    // fire on a non-credential. The compound spellings below are not.
    static const std::vector<std::string> kCredentialShapedSuffixes = {
        "_secret",     "_password",   "_token",      "_key_material", "_credential",
        "_api_key",    "_access_key", "_secret_key", "_private_key",  "_passphrase",
        "_client_key", "_signing_key",
    };

    for (const auto& key : RuntimeConfigStore::allowed_keys()) {
        for (const auto& suffix : kCredentialShapedSuffixes) {
            if (key.size() >= suffix.size() &&
                key.compare(key.size() - suffix.size(), suffix.size(), suffix) == 0) {
                INFO("allowed key '" << key << "' is spelled like a credential but is not in "
                                              "kSecretKeys, so its value would be written to the "
                                              "startup log and returned by GET /api/config");
                CHECK(RuntimeConfigStore::is_secret_key(key));
            }
        }
    }
}

TEST_CASE("every registered secret key is actually storable", "[runtime_config][secret]") {
    // A secret key that is not in `allowed_keys()` can never be set, so its presence in
    // the secret list is dead weight and, worse, implies coverage that does not exist.
    const auto& allowed = RuntimeConfigStore::allowed_keys();
    CHECK(std::find(allowed.begin(), allowed.end(), std::string("oidc_client_secret")) !=
          allowed.end());
}

// The store-level contract is the part that makes a FUTURE emitter safe: get_all()
// redacts by default, and plaintext requires asking for it by name. Redaction being
// opt-in at the emitter is exactly how the plaintext value reached an audit row that
// every AuditLog:Read holder (Operator among them) can read -- a durable sink that
// cannot be rotated away, and one this file's earlier tests passed straight over
// because they only checked key REGISTRATION, never emitter consultation.
TEST_CASE("get_all() redacts secrets; get_all_with_secrets() does not",
          "[runtime_config][secret]") {
    auto db = yuzu::test::unique_temp_path("yuzu_test_rtcfg");
    {
        RuntimeConfigStore store(db);
        REQUIRE(store.is_open());
        REQUIRE(store.set("oidc_client_secret", "s3cr3t-value", "tester"));
        REQUIRE(store.set("oidc_issuer", "https://idp.example.com", "tester"));

        std::string redacted_secret, redacted_issuer, real_secret, real_issuer;
        for (const auto& e : store.get_all()) {
            if (e.key == "oidc_client_secret") redacted_secret = e.value;
            if (e.key == "oidc_issuer")        redacted_issuer = e.value;
        }
        for (const auto& e : store.get_all_with_secrets()) {
            if (e.key == "oidc_client_secret") real_secret = e.value;
            if (e.key == "oidc_issuer")        real_issuer = e.value;
        }

        // The default must never hand back the credential.
        CHECK(redacted_secret == RuntimeConfigStore::redacted_placeholder());
        CHECK(redacted_secret != "s3cr3t-value");
        // A non-secret key is untouched by either accessor -- redacting configuration
        // would cost real diagnostic signal.
        CHECK(redacted_issuer == "https://idp.example.com");
        // The named accessor still works, or the startup override pass breaks.
        CHECK(real_secret == "s3cr3t-value");
        CHECK(real_issuer == "https://idp.example.com");
    }
    std::error_code ec;
    std::filesystem::remove(db, ec);
}

TEST_CASE("an EMPTY secret survives redaction as empty, so is_set can be false",
          "[runtime_config][secret]") {
    // GET /api/config reports `is_set` as !value.empty() on the REDACTED entry.
    // Replacing every secret value -- including "" -- with the non-empty placeholder
    // made that unconditionally true: no stored secret could report unset. Caught by
    // review after the redaction landed, which is why it has its own case.
    auto db = yuzu::test::unique_temp_path("yuzu_test_rtcfg_empty");
    {
        RuntimeConfigStore store(db);
        REQUIRE(store.is_open());
        REQUIRE(store.set("oidc_client_secret", "", "tester"));

        std::string v;
        bool found = false;
        for (const auto& e : store.get_all()) {
            if (e.key == "oidc_client_secret") { v = e.value; found = true; }
        }
        REQUIRE(found);
        CHECK(v.empty());
        CHECK(v != RuntimeConfigStore::redacted_placeholder());

        // And a non-empty one still redacts, or the fix for the emptiness case would
        // have been "stop redacting".
        REQUIRE(store.set("oidc_client_secret", "real", "tester"));
        for (const auto& e : store.get_all()) {
            if (e.key == "oidc_client_secret")
                CHECK(e.value == RuntimeConfigStore::redacted_placeholder());
        }
    }
    std::error_code ec;
    std::filesystem::remove(db, ec);
}
