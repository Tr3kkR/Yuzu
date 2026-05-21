/**
 * test_webhook_store.cpp -- Unit tests for WebhookStore
 *
 * Covers: open, create, list, delete, URL scheme validation, deliveries.
 */

#include "webhook_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("WebhookStore: open in-memory", "[webhook_store][db]") {
    WebhookStore store(":memory:");
    REQUIRE(store.is_open());
}

// ── Create and list ────────────────────────────────────────────────────────

TEST_CASE("WebhookStore: create and list webhook", "[webhook_store]") {
    WebhookStore store(":memory:");

    auto id = store.create_webhook("https://example.com/hook", "agent.registered", "secret123");
    REQUIRE(id > 0);

    auto hooks = store.list();
    REQUIRE(hooks.size() == 1);
    CHECK(hooks[0].url == "https://example.com/hook");
    CHECK(hooks[0].event_types == "agent.registered");
    CHECK(hooks[0].secret.empty());  // list() redacts secrets by design
    CHECK(hooks[0].enabled == true);
    CHECK(hooks[0].id == id);
}

// ── Multiple webhooks ──────────────────────────────────────────────────────

TEST_CASE("WebhookStore: multiple webhooks", "[webhook_store]") {
    WebhookStore store(":memory:");

    store.create_webhook("https://a.com/hook", "agent.registered", "s1");
    store.create_webhook("https://b.com/hook", "execution.completed", "s2");
    store.create_webhook("http://c.com/hook", "agent.heartbeat", "s3");

    auto hooks = store.list();
    REQUIRE(hooks.size() == 3);
}

// ── Delete webhook ─────────────────────────────────────────────────────────

TEST_CASE("WebhookStore: delete webhook", "[webhook_store]") {
    WebhookStore store(":memory:");

    auto id = store.create_webhook("https://example.com/hook", "agent.registered", "secret");
    REQUIRE(store.list().size() == 1);

    bool deleted = store.delete_webhook(id);
    CHECK(deleted);
    CHECK(store.list().empty());
}

TEST_CASE("WebhookStore: delete nonexistent webhook returns false", "[webhook_store]") {
    WebhookStore store(":memory:");

    bool deleted = store.delete_webhook(99999);
    CHECK_FALSE(deleted);
}

// ── URL scheme validation (L12) ────────────────────────────────────────────

TEST_CASE("WebhookStore: rejects invalid URL scheme", "[webhook_store][security]") {
    WebhookStore store(":memory:");

    // ftp:// should be rejected
    auto id1 = store.create_webhook("ftp://example.com/hook", "agent.registered", "secret");
    CHECK(id1 == -1);

    // javascript: should be rejected
    auto id2 = store.create_webhook("javascript:alert(1)", "agent.registered", "secret");
    CHECK(id2 == -1);

    // Empty URL should be rejected
    auto id3 = store.create_webhook("", "agent.registered", "secret");
    CHECK(id3 == -1);

    // Valid schemes should be accepted
    auto id4 = store.create_webhook("https://example.com/hook", "agent.registered", "secret");
    CHECK(id4 > 0);

    auto id5 = store.create_webhook("http://example.com/hook", "agent.registered", "secret");
    CHECK(id5 > 0);
}

TEST_CASE("WebhookStore: rejects internal webhook hosts", "[webhook_store][security]") {
    WebhookStore store(":memory:");

    CHECK(store.create_webhook("http://127.0.0.1:8080/hook", "agent.registered",
                               "secret") == -1);
    CHECK(store.create_webhook("http://localhost:50051/hook", "agent.registered",
                               "secret") == -1);
    CHECK(store.create_webhook("http://169.254.169.254/latest/meta-data",
                               "agent.registered", "secret") == -1);
    CHECK(store.create_webhook("http://10.0.0.5/hook", "agent.registered",
                               "secret") == -1);
    CHECK(store.create_webhook("http://172.16.0.5/hook", "agent.registered",
                               "secret") == -1);
    CHECK(store.create_webhook("http://192.168.1.5/hook", "agent.registered",
                               "secret") == -1);
    CHECK(store.create_webhook("http://[::1]:50051/hook", "agent.registered",
                               "secret") == -1);
    CHECK(store.create_webhook("http://[fc00::1]/hook", "agent.registered",
                               "secret") == -1);
    CHECK(store.create_webhook("http://[::ffff:7f00:1]/hook", "agent.registered",
                               "secret") == -1);
    CHECK(store.create_webhook("http://[::ffff:a00:1]/hook", "agent.registered",
                               "secret") == -1);
    CHECK(store.create_webhook("http://agent.local/hook", "agent.registered",
                               "secret") == -1);
    CHECK(store.create_webhook("http://api.internal/hook", "agent.registered",
                               "secret") == -1);
    CHECK(store.create_webhook("http://2130706433/hook", "agent.registered",
                               "secret") == -1);
    CHECK(store.create_webhook("http://0177.0.0.1/hook", "agent.registered",
                               "secret") == -1);

    CHECK(store.create_webhook("https://example.com/hook", "agent.registered",
                               "secret") > 0);
    CHECK(store.create_webhook("http://93.184.216.34/hook", "agent.registered",
                               "secret") > 0);
    CHECK(store.create_webhook("http://[::ffff:5db8:d822]/hook", "agent.registered",
                               "secret") > 0);
}

// ── Empty store ────────────────────────────────────────────────────────────

TEST_CASE("WebhookStore: empty store returns empty list", "[webhook_store]") {
    WebhookStore store(":memory:");
    CHECK(store.list().empty());
}

// ── Deliveries on empty webhook ────────────────────────────────────────────

TEST_CASE("WebhookStore: get_deliveries on empty webhook returns empty", "[webhook_store]") {
    WebhookStore store(":memory:");

    auto id = store.create_webhook("https://example.com/hook", "agent.registered", "secret");
    auto deliveries = store.get_deliveries(id);
    CHECK(deliveries.empty());
}
