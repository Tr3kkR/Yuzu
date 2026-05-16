/**
 * test_agent_registry_token_revocation.cpp — W1.5 / #823.
 *
 * AgentRegistry::register_agent MUST revoke any device tokens previously
 * issued under a re-registering agent_id. Without this, an attacker who
 * briefly impersonated the agent (mTLS-disabled flow, #779) keeps replay
 * access to every token ever issued to that identity, because the prior
 * tokens stay `revoked = 0` in `device_auth_tokens`.
 *
 * Scope of this file: the wiring contract between AgentRegistry and
 * DeviceTokenStore. Pure store behaviour (idempotency, empty-principal
 * guard, "alice's revoke doesn't touch bob's") lives in
 * `test_device_token_store.cpp`.
 */

#include "agent_registry.hpp"
#include "device_token_store.hpp"
#include "event_bus.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include "agent.pb.h"

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
// `pb` is already bound to `::yuzu::agent::v1` by agent_registry.hpp inside
// `namespace yuzu::server::detail`. We can't use a file-scope alias of the
// same name without "redefinition of 'pb'"; use `agent_pb` here instead.
namespace agent_pb = ::yuzu::agent::v1;

namespace {

agent_pb::AgentInfo make_info(const std::string& id, const std::string& host = "host.local") {
    agent_pb::AgentInfo info;
    info.set_agent_id(id);
    info.set_hostname(host);
    return info;
}

} // namespace

TEST_CASE("AgentRegistry: re-registering an agent revokes that agent's device tokens",
          "[agent_registry][823][token_revocation]") {
    // Threat model: attacker re-registers under endpoint-99 (mTLS-disabled
    // impersonation, #779). The token previously issued to the legitimate
    // endpoint-99 must be revoked before the attacker's session is live, so
    // the attacker cannot replay the stolen token against any device-token-
    // authenticated REST endpoint.
    yuzu::test::TempDbFile tdb{std::string_view{"agent-reg-token-rev-"}};
    DeviceTokenStore tokens(tdb.path);
    REQUIRE(tokens.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.set_device_token_store(&tokens);

    // Legitimate endpoint-99 lifecycle: register, then operator issues a
    // device-bound token, then validate succeeds.
    registry.register_agent(make_info("endpoint-99"));
    auto raw = tokens.create_token("legit", "endpoint-99", "endpoint-99", "", 0);
    REQUIRE(raw.has_value());
    REQUIRE(tokens.validate_token(*raw, "endpoint-99").has_value());

    // Attacker re-registers as endpoint-99. Per the W1.5 wiring, the prior
    // device tokens for that agent_id must be revoked atomically with the
    // session swap.
    registry.register_agent(make_info("endpoint-99", "attacker.local"));

    auto reval = tokens.validate_token(*raw, "endpoint-99");
    REQUIRE(!reval.has_value());
    CHECK(reval.error().error == DeviceTokenValidateError::revoked);
    CHECK(reval.error().bound_principal_id == "endpoint-99");
}

TEST_CASE("AgentRegistry: first-time registration does NOT revoke pre-issued tokens",
          "[agent_registry][823][token_revocation]") {
    // Operator workflow: pre-issue a device-bound token for an agent_id
    // that has not registered yet (legitimate enrollment automation). The
    // first-ever register_agent for that id must leave the pre-issued
    // token alone — only re-registration is the attack surface #823 closes.
    yuzu::test::TempDbFile tdb{std::string_view{"agent-reg-token-rev-firsttime-"}};
    DeviceTokenStore tokens(tdb.path);
    REQUIRE(tokens.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.set_device_token_store(&tokens);

    auto raw = tokens.create_token("preissued", "endpoint-7", "endpoint-7", "", 0);
    REQUIRE(raw.has_value());

    // No prior register — this is the first time the registry sees endpoint-7.
    registry.register_agent(make_info("endpoint-7"));

    // The pre-issued token must survive: validate still succeeds.
    REQUIRE(tokens.validate_token(*raw, "endpoint-7").has_value());
}

TEST_CASE("AgentRegistry: re-register for one agent_id leaves other agents' tokens alone",
          "[agent_registry][823][token_revocation]") {
    // Confidence check: the revoke is keyed on the re-registering agent_id,
    // not the whole table. Bob's token must survive alice's re-register.
    yuzu::test::TempDbFile tdb{std::string_view{"agent-reg-token-rev-isolation-"}};
    DeviceTokenStore tokens(tdb.path);
    REQUIRE(tokens.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.set_device_token_store(&tokens);

    registry.register_agent(make_info("alice"));
    registry.register_agent(make_info("bob"));
    auto alice_tok = tokens.create_token("a", "alice", "alice", "", 0);
    auto bob_tok = tokens.create_token("b", "bob", "bob", "", 0);
    REQUIRE(alice_tok.has_value());
    REQUIRE(bob_tok.has_value());

    // Re-register alice. Bob's token must not be touched.
    registry.register_agent(make_info("alice"));

    auto a_after = tokens.validate_token(*alice_tok, "alice");
    REQUIRE(!a_after.has_value());
    CHECK(a_after.error().error == DeviceTokenValidateError::revoked);

    REQUIRE(tokens.validate_token(*bob_tok, "bob").has_value());
}

TEST_CASE("AgentRegistry: register_agent without a DeviceTokenStore wired is safe",
          "[agent_registry][823][token_revocation]") {
    // Defensive default: if `set_device_token_store` was never called (the
    // current production path — server.cpp doesn't yet construct a
    // DeviceTokenStore), register_agent must behave exactly as before:
    // no crash, no revoke. The W1.5 wiring exists so the invariant is in
    // place the moment production wires the store up.
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);

    registry.register_agent(make_info("endpoint-X"));
    registry.register_agent(make_info("endpoint-X")); // re-register — must not crash
    CHECK(registry.agent_count() == 1);
}
