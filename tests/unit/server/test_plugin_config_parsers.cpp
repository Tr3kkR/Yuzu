// test_plugin_config_parsers.cpp — fixture tests for the pure plugin config
// key grammar / value caps / kill-switch scope normalization / secret
// redaction helpers (PR1.5b). OS-independent: no I/O, no store, no httplib,
// no pg — plugin_config_parsers.hpp has zero includes of any of those, and
// these tests spawn nothing.

#include "plugin_config_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server::plugin_config;

// ── Identifier grammar ──────────────────────────────────────────────────

TEST_CASE("is_valid_identifier accepts lowercase alnum/underscore starting with a letter",
          "[server][config]") {
    CHECK(is_valid_identifier("email"));
    CHECK(is_valid_identifier("email_gateway"));
    CHECK(is_valid_identifier("a"));
    CHECK(is_valid_identifier("a1"));
    CHECK(is_valid_identifier(std::string(kMaxIdentifierBytes, 'a')));
}

TEST_CASE("is_valid_identifier rejects empty, oversized, uppercase, leading-digit, hyphen, dot",
          "[server][config]") {
    CHECK_FALSE(is_valid_identifier(""));
    CHECK_FALSE(is_valid_identifier(std::string(kMaxIdentifierBytes + 1, 'a')));
    CHECK_FALSE(is_valid_identifier("Email"));
    CHECK_FALSE(is_valid_identifier("1email"));
    CHECK_FALSE(is_valid_identifier("email-gateway"));
    CHECK_FALSE(is_valid_identifier("email.gateway"));
    CHECK_FALSE(is_valid_identifier("_email"));
    CHECK_FALSE(is_valid_identifier("email "));
}

TEST_CASE("is_valid_key accepts dot-segmented identifiers, rejects leading/trailing/doubled dots",
          "[server][config]") {
    CHECK(is_valid_key("host"));
    CHECK(is_valid_key("smtp.host"));
    CHECK(is_valid_key("smtp.host.port"));
    CHECK_FALSE(is_valid_key(""));
    CHECK_FALSE(is_valid_key(".host"));
    CHECK_FALSE(is_valid_key("host."));
    CHECK_FALSE(is_valid_key("smtp..host"));
    CHECK_FALSE(is_valid_key(std::string(kMaxKeyBytes + 1, 'a')));
    CHECK_FALSE(is_valid_key("smtp.Host"));
}

TEST_CASE("parse_plugin_key round-trips through canonical_plugin_key", "[server][config]") {
    auto pk = parse_plugin_key("email", "smtp.host");
    REQUIRE(pk.has_value());
    CHECK(pk->plugin == "email");
    CHECK(pk->key == "smtp.host");
    CHECK(canonical_plugin_key(*pk) == "email.smtp.host");
}

TEST_CASE("parse_plugin_key rejects an invalid plugin or key", "[server][config]") {
    CHECK_FALSE(parse_plugin_key("Email", "host").has_value());
    CHECK_FALSE(parse_plugin_key("email", "").has_value());
    CHECK_FALSE(parse_plugin_key("", "host").has_value());
}

// ── Value caps ───────────────────────────────────────────────────────────

TEST_CASE("is_valid_config_value enforces the size cap and rejects an embedded NUL",
          "[server][config]") {
    CHECK(is_valid_config_value(""));
    CHECK(is_valid_config_value(std::string(kMaxConfigValueBytes, 'x')));
    CHECK_FALSE(is_valid_config_value(std::string(kMaxConfigValueBytes + 1, 'x')));
    std::string with_nul = "abc";
    with_nul.push_back('\0');
    with_nul += "def";
    CHECK_FALSE(is_valid_config_value(with_nul));
}

TEST_CASE("is_valid_secret_value requires non-empty and enforces the size cap, NUL is fine",
          "[server][config]") {
    CHECK_FALSE(is_valid_secret_value(""));
    CHECK(is_valid_secret_value("s"));
    CHECK(is_valid_secret_value(std::string(kMaxSecretValueBytes, 'x')));
    CHECK_FALSE(is_valid_secret_value(std::string(kMaxSecretValueBytes + 1, 'x')));
    std::string with_nul = "abc";
    with_nul.push_back('\0');
    with_nul += "def";
    CHECK(is_valid_secret_value(with_nul)); // secrets are opaque bytes, not TEXT
}

TEST_CASE("has_embedded_nul finds a NUL anywhere in the string", "[server][config]") {
    CHECK_FALSE(has_embedded_nul("clean"));
    std::string s = "a";
    s.push_back('\0');
    CHECK(has_embedded_nul(s));
}

// ── Kill-switch scope ────────────────────────────────────────────────────

TEST_CASE("parse_kill_switch_scope: empty action is whole-plugin, non-empty must be an identifier",
          "[server][config]") {
    auto whole = parse_kill_switch_scope("email", "");
    REQUIRE(whole.has_value());
    CHECK(whole->plugin == "email");
    CHECK(whole->action.empty());

    auto one = parse_kill_switch_scope("email", "send");
    REQUIRE(one.has_value());
    CHECK(one->action == "send");

    CHECK_FALSE(parse_kill_switch_scope("email", "send.now").has_value()); // action is one segment
    CHECK_FALSE(parse_kill_switch_scope("Email", "send").has_value());
}

TEST_CASE("kill_switch_scope_key is <plugin> for whole-plugin, <plugin>.<action> otherwise",
          "[server][config]") {
    CHECK(kill_switch_scope_key({"email", ""}) == "email");
    CHECK(kill_switch_scope_key({"email", "send"}) == "email.send");
}

TEST_CASE("kill_switch_scope_key never collides a plugin-level and an action-level scope",
          "[server][config]") {
    // A plugin literally named "email.send" cannot exist (plugin grammar
    // forbids dots), so the two scope kinds cannot collide via this route —
    // pin that the two keys stay textually distinct for the pairs that DO
    // parse.
    const auto plugin_level = kill_switch_scope_key({"email", ""});
    const auto action_level = kill_switch_scope_key({"email", "send"});
    CHECK(plugin_level != action_level);
}

TEST_CASE("is_valid_reason enforces the size cap and rejects control characters",
          "[server][config]") {
    CHECK(is_valid_reason(""));
    CHECK(is_valid_reason("incident #1234, throttling outbound mail"));
    CHECK(is_valid_reason(std::string(kMaxReasonBytes, 'x')));
    CHECK_FALSE(is_valid_reason(std::string(kMaxReasonBytes + 1, 'x')));
    CHECK_FALSE(is_valid_reason(std::string("bad\r\ninjected header")));
    CHECK_FALSE(is_valid_reason(std::string(1, '\0')));
    CHECK(is_valid_reason("tab\tallowed"));
}

TEST_CASE("is_valid_actor enforces non-empty, size cap, and no control characters",
          "[server][config]") {
    CHECK(is_valid_actor("alice"));
    CHECK(is_valid_actor("oidc:https://idp.example#sub-123"));
    CHECK(is_valid_actor("engine:svc-slug"));
    CHECK_FALSE(is_valid_actor(""));
    CHECK_FALSE(is_valid_actor(std::string(kMaxActorBytes + 1, 'a')));
    CHECK_FALSE(is_valid_actor(std::string("alice\n")));
}

// ── Secret redaction ─────────────────────────────────────────────────────

TEST_CASE("redact_secret_for_audit never embeds a value — its signature has no value parameter",
          "[server][config]") {
    PluginKey pk{"email", "smtp.password"};
    const std::string detail = redact_secret_for_audit(pk);
    CHECK(detail.find("email") != std::string::npos);
    CHECK(detail.find("smtp.password") != std::string::npos);
    CHECK(detail.find(std::string(kRedactedSecretPlaceholder)) != std::string::npos);
    // There is no plaintext anywhere for this assertion to even look for —
    // the function signature makes leaking one structurally impossible; this
    // pins the placeholder text stays present so a future edit can't quietly
    // drop it.
}

TEST_CASE("redact_secret_for_log never embeds a value — its signature has no value parameter",
          "[server][config]") {
    PluginKey pk{"email", "smtp.password"};
    const std::string line = redact_secret_for_log(pk);
    CHECK(line.find("email") != std::string::npos);
    CHECK(line.find("smtp.password") != std::string::npos);
    CHECK(line.find(std::string(kRedactedSecretPlaceholder)) != std::string::npos);
}
