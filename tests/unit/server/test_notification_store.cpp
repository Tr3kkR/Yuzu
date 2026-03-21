/**
 * test_notification_store.cpp -- Unit tests for NotificationStore
 *
 * Covers: open, create, list_unread, list_all, mark_read, dismiss, count_unread.
 */

#include "notification_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::server;

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: open in-memory", "[notification_store][db]") {
    NotificationStore store(":memory:");
    REQUIRE(store.is_open());
}

// ── Create and retrieve ────────────────────────────────────────────────────

TEST_CASE("NotificationStore: create and list_unread", "[notification_store]") {
    NotificationStore store(":memory:");

    auto id = store.create("info", "Agent connected", "Agent abc123 registered successfully");
    REQUIRE(id > 0);

    auto unread = store.list_unread();
    REQUIRE(unread.size() == 1);
    CHECK(unread[0].level == "info");
    CHECK(unread[0].title == "Agent connected");
    CHECK(unread[0].message == "Agent abc123 registered successfully");
    CHECK(unread[0].read == false);
    CHECK(unread[0].dismissed == false);
}

// ── Multiple notifications ─────────────────────────────────────────────────

TEST_CASE("NotificationStore: multiple creates and list_all", "[notification_store]") {
    NotificationStore store(":memory:");

    store.create("info", "First", "First message");
    store.create("warn", "Second", "Second message");
    store.create("error", "Third", "Third message");

    auto all = store.list_all();
    REQUIRE(all.size() == 3);
    // Newest first
    CHECK(all[0].title == "Third");
    CHECK(all[1].title == "Second");
    CHECK(all[2].title == "First");
}

// ── Mark read ──────────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: mark_read removes from unread", "[notification_store]") {
    NotificationStore store(":memory:");

    auto id = store.create("info", "Test", "Test notification");
    REQUIRE(store.count_unread() == 1);

    store.mark_read(id);

    auto unread = store.list_unread();
    CHECK(unread.empty());
    CHECK(store.count_unread() == 0);

    // Should still appear in list_all
    auto all = store.list_all();
    REQUIRE(all.size() == 1);
    CHECK(all[0].read == true);
}

// ── Dismiss ────────────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: dismiss removes from unread", "[notification_store]") {
    NotificationStore store(":memory:");

    auto id = store.create("warn", "Alert", "Something happened");
    REQUIRE(store.count_unread() == 1);

    store.dismiss(id);

    CHECK(store.count_unread() == 0);
    auto unread = store.list_unread();
    CHECK(unread.empty());
}

// ── Count unread ───────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: count_unread tracks correctly", "[notification_store]") {
    NotificationStore store(":memory:");

    CHECK(store.count_unread() == 0);

    auto id1 = store.create("info", "A", "msg");
    auto id2 = store.create("info", "B", "msg");
    store.create("error", "C", "msg");

    CHECK(store.count_unread() == 3);

    store.mark_read(id1);
    CHECK(store.count_unread() == 2);

    store.dismiss(id2);
    CHECK(store.count_unread() == 1);
}

// ── Empty store ────────────────────────────────────────────────────────────

TEST_CASE("NotificationStore: empty store returns empty lists", "[notification_store]") {
    NotificationStore store(":memory:");

    CHECK(store.list_unread().empty());
    CHECK(store.list_all().empty());
    CHECK(store.count_unread() == 0);
}
