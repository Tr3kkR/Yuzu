/**
 * test_analytics_event.cpp — Unit tests for AnalyticsEvent and AnalyticsEventStore
 *
 * Covers: JSON serialization, severity enum, store lifecycle, emit/query,
 * drain to sinks, concurrent emit, schema version preservation.
 */

#include "analytics_event.hpp"
#include "analytics_event_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;

// ── Mock sink for testing ──────────────────────────────────────────────────

class MockSink : public AnalyticsEventSink {
public:
    bool send(std::span<const AnalyticsEvent> batch) override {
        std::lock_guard lock(mu_);
        for (const auto& e : batch) {
            received_.push_back(e);
        }
        ++send_count_;
        return should_succeed_;
    }

    std::string name() const override { return "mock"; }

    std::vector<AnalyticsEvent> received() const {
        std::lock_guard lock(mu_);
        return received_;
    }

    int send_count() const {
        std::lock_guard lock(mu_);
        return send_count_;
    }

    void set_should_succeed(bool v) { should_succeed_ = v; }

private:
    mutable std::mutex mu_;
    std::vector<AnalyticsEvent> received_;
    int send_count_{0};
    bool should_succeed_{true};
};

// ── JSON Serialization ─────────────────────────────────────────────────────

TEST_CASE("AnalyticsEvent: JSON round-trip with all fields", "[analytics_event][json]") {
    AnalyticsEvent event;
    event.tenant_id = "acme";
    event.agent_id = "agent-001";
    event.session_id = "sess-xyz";
    event.event_type = "command.completed";
    event.event_time = 1700000000000;
    event.ingest_time = 1700000001000;
    event.plugin = "netstat";
    event.capability = "list_connections";
    event.correlation_id = "cmd-abc123";
    event.severity = Severity::kWarn;
    event.source = "server";
    event.hostname = "host-01";
    event.os = "linux";
    event.arch = "x86_64";
    event.agent_version = "1.2.3";
    event.principal = "admin";
    event.principal_role = "admin";
    event.attributes = {{"target_count", 5}};
    event.payload = {{"status", "SUCCESS"}, {"exit_code", 0}};
    event.schema_version = 1;

    nlohmann::json j = event;
    auto restored = j.get<AnalyticsEvent>();

    CHECK(restored.tenant_id == "acme");
    CHECK(restored.agent_id == "agent-001");
    CHECK(restored.session_id == "sess-xyz");
    CHECK(restored.event_type == "command.completed");
    CHECK(restored.event_time == 1700000000000);
    CHECK(restored.ingest_time == 1700000001000);
    CHECK(restored.plugin == "netstat");
    CHECK(restored.capability == "list_connections");
    CHECK(restored.correlation_id == "cmd-abc123");
    CHECK(restored.severity == Severity::kWarn);
    CHECK(restored.source == "server");
    CHECK(restored.hostname == "host-01");
    CHECK(restored.os == "linux");
    CHECK(restored.arch == "x86_64");
    CHECK(restored.agent_version == "1.2.3");
    CHECK(restored.principal == "admin");
    CHECK(restored.principal_role == "admin");
    CHECK(restored.attributes["target_count"] == 5);
    CHECK(restored.payload["status"] == "SUCCESS");
    CHECK(restored.payload["exit_code"] == 0);
    CHECK(restored.schema_version == 1);
}

TEST_CASE("AnalyticsEvent: JSON round-trip with defaults", "[analytics_event][json]") {
    AnalyticsEvent event;
    event.event_type = "auth.login";

    nlohmann::json j = event;
    auto restored = j.get<AnalyticsEvent>();

    CHECK(restored.tenant_id == "default");
    CHECK(restored.agent_id.empty());
    CHECK(restored.event_type == "auth.login");
    CHECK(restored.event_time == 0);
    CHECK(restored.severity == Severity::kInfo);
    CHECK(restored.source == "server");
    CHECK(restored.schema_version == 1);
    CHECK(restored.attributes.is_object());
    CHECK(restored.payload.is_object());
}

TEST_CASE("AnalyticsEvent: JSON with empty optional fields", "[analytics_event][json]") {
    AnalyticsEvent event;
    event.event_type = "agent.registered";
    event.agent_id = "agent-002";

    nlohmann::json j = event;

    // All fields present in JSON even if empty
    CHECK(j.contains("plugin"));
    CHECK(j.contains("principal"));
    CHECK(j["plugin"] == "");
    CHECK(j["principal"] == "");

    auto restored = j.get<AnalyticsEvent>();
    CHECK(restored.plugin.empty());
    CHECK(restored.principal.empty());
}

// ── Severity Enum ──────────────────────────────────────────────────────────

TEST_CASE("Severity: serialization round-trip", "[analytics_event][severity]") {
    CHECK(severity_to_string(Severity::kDebug) == "debug");
    CHECK(severity_to_string(Severity::kInfo) == "info");
    CHECK(severity_to_string(Severity::kWarn) == "warn");
    CHECK(severity_to_string(Severity::kError) == "error");
    CHECK(severity_to_string(Severity::kCritical) == "critical");

    CHECK(severity_from_string("debug") == Severity::kDebug);
    CHECK(severity_from_string("info") == Severity::kInfo);
    CHECK(severity_from_string("warn") == Severity::kWarn);
    CHECK(severity_from_string("error") == Severity::kError);
    CHECK(severity_from_string("critical") == Severity::kCritical);
    CHECK(severity_from_string("unknown") == Severity::kInfo); // default
}

// ── Store Lifecycle ────────────────────────────────────────────────────────

TEST_CASE("AnalyticsEventStore: open in-memory", "[analytics_store][db]") {
    AnalyticsEventStore store(":memory:");
    REQUIRE(store.is_open());
}

TEST_CASE("AnalyticsEventStore: emit and query_recent", "[analytics_store]") {
    AnalyticsEventStore store(":memory:");

    AnalyticsEvent event;
    event.event_type = "agent.registered";
    event.agent_id = "agent-001";
    store.emit(event);

    auto results = store.query_recent();
    REQUIRE(results.size() == 1);
    CHECK(results[0].event_type == "agent.registered");
    CHECK(results[0].agent_id == "agent-001");
    CHECK(results[0].ingest_time > 0);
}

TEST_CASE("AnalyticsEventStore: pending_count and total_emitted", "[analytics_store]") {
    AnalyticsEventStore store(":memory:");
    REQUIRE(store.pending_count() == 0);
    REQUIRE(store.total_emitted() == 0);

    for (int i = 0; i < 5; ++i) {
        AnalyticsEvent event;
        event.event_type = "test.event";
        store.emit(event);
    }

    CHECK(store.pending_count() == 5);
    CHECK(store.total_emitted() == 5);
}

// ── Drain to Sink ──────────────────────────────────────────────────────────

TEST_CASE("AnalyticsEventStore: drain to mock sink", "[analytics_store][drain]") {
    // Use drain_interval=1 for fast test
    AnalyticsEventStore store(":memory:", /*drain_interval=*/1, /*batch_size=*/100);

    auto sink = std::make_unique<MockSink>();
    auto* sink_ptr = sink.get();
    store.add_sink(std::move(sink));

    for (int i = 0; i < 3; ++i) {
        AnalyticsEvent event;
        event.event_type = "test.event";
        event.correlation_id = "id-" + std::to_string(i);
        store.emit(event);
    }

    CHECK(store.pending_count() == 3);

    store.start_drain();
    // Wait for drain cycle
    std::this_thread::sleep_for(std::chrono::seconds(3));
    store.stop_drain();

    auto received = sink_ptr->received();
    REQUIRE(received.size() == 3);
    CHECK(store.pending_count() == 0);
}

TEST_CASE("AnalyticsEventStore: drained events not re-sent", "[analytics_store][drain]") {
    AnalyticsEventStore store(":memory:", 1, 100);

    auto sink = std::make_unique<MockSink>();
    auto* sink_ptr = sink.get();
    store.add_sink(std::move(sink));

    AnalyticsEvent event;
    event.event_type = "test.once";
    store.emit(event);

    store.start_drain();
    std::this_thread::sleep_for(std::chrono::seconds(3));
    store.stop_drain();

    // Should have been sent exactly once
    auto received = sink_ptr->received();
    REQUIRE(received.size() == 1);
    CHECK(received[0].event_type == "test.once");

    // Total emitted is still 1
    CHECK(store.total_emitted() == 1);
    CHECK(store.pending_count() == 0);
}

TEST_CASE("AnalyticsEventStore: sink failure keeps events pending", "[analytics_store][drain]") {
    AnalyticsEventStore store(":memory:", 1, 100);

    auto sink = std::make_unique<MockSink>();
    auto* sink_ptr = sink.get();
    sink_ptr->set_should_succeed(false);
    store.add_sink(std::move(sink));

    AnalyticsEvent event;
    event.event_type = "test.fail";
    store.emit(event);

    store.start_drain();
    std::this_thread::sleep_for(std::chrono::seconds(3));
    store.stop_drain();

    // Sink received the batch but failed — events should still be pending
    CHECK(sink_ptr->send_count() > 0);
    CHECK(store.pending_count() == 1);
}

TEST_CASE("AnalyticsEventStore: concurrent emit from multiple threads",
          "[analytics_store][threads]") {
    AnalyticsEventStore store(":memory:");

    constexpr int kThreads = 4;
    constexpr int kPerThread = 25;

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&store, t]() {
            for (int i = 0; i < kPerThread; ++i) {
                AnalyticsEvent event;
                event.event_type = "thread.event";
                event.correlation_id = std::to_string(t) + "-" + std::to_string(i);
                store.emit(event);
            }
        });
    }
    for (auto& th : threads)
        th.join();

    CHECK(store.total_emitted() == kThreads * kPerThread);
}

TEST_CASE("AnalyticsEvent: schema_version preserved", "[analytics_event][json]") {
    AnalyticsEvent event;
    event.event_type = "test";
    event.schema_version = 42;

    nlohmann::json j = event;
    auto restored = j.get<AnalyticsEvent>();
    CHECK(restored.schema_version == 42);
}

TEST_CASE("AnalyticsEvent: event_time auto-stamped by emit", "[analytics_store]") {
    AnalyticsEventStore store(":memory:");

    AnalyticsEvent event;
    event.event_type = "test.autotime";
    // event_time left at 0 — should be stamped by emit()
    store.emit(event);

    auto results = store.query_recent();
    REQUIRE(results.size() == 1);
    CHECK(results[0].event_time > 0);
    CHECK(results[0].ingest_time > 0);
    CHECK(results[0].event_time == results[0].ingest_time);
}
