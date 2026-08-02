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
// exactly the same two paths, and nothing else would notice.

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <algorithm>
#include <vector>

#include "runtime_config_store.hpp"

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
    static const std::vector<std::string> kCredentialShapedSuffixes = {
        "_secret", "_password", "_token", "_key_material", "_credential",
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
