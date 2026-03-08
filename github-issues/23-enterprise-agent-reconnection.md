---
title: "[P2/ENT] Implement agent reconnection with exponential backoff"
labels: enhancement, enterprise, P2, reliability
assignees: ""
---

## Summary

The agent does not reconnect if the server restarts or the network drops. Once the gRPC stream breaks, the agent exits. Enterprise deployments require automatic reconnection with exponential backoff for high availability.

## Affected Files

- `agents/core/src/agent.cpp` — `run()` method

## Current Behavior

The agent's `run()` method establishes a single connection. If `Register()` fails or the `Subscribe()` stream breaks, the agent logs an error and exits.

## Recommended Implementation

```cpp
void Agent::run() {
    constexpr auto kInitialBackoff = std::chrono::seconds(1);
    constexpr auto kMaxBackoff = std::chrono::seconds(60);
    constexpr int kMaxRetries = -1;  // Infinite

    auto backoff = kInitialBackoff;
    int attempt = 0;

    while (!shutdown_requested_.load()) {
        attempt++;
        spdlog::info("Connection attempt {} to {}", attempt, cfg_.server_address);

        auto result = connect_and_run();  // Current run() logic extracted

        if (shutdown_requested_.load()) break;

        spdlog::warn("Disconnected from server (attempt {}), retrying in {}s",
            attempt, backoff.count());

        // Wait with shutdown check
        auto deadline = std::chrono::steady_clock::now() + backoff;
        while (std::chrono::steady_clock::now() < deadline && !shutdown_requested_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        // Exponential backoff with jitter
        backoff = std::min(backoff * 2, kMaxBackoff);
        // Add ±25% jitter
        std::uniform_int_distribution<int> jitter(-25, 25);
        std::random_device rd;
        auto jitter_ms = backoff.count() * jitter(rd) / 100;
        backoff += std::chrono::seconds(jitter_ms / 1000);
    }
}
```

### Re-registration

On reconnect, the agent must:
1. Re-register with the server (new session ID)
2. Re-subscribe to the command stream
3. Plugins remain loaded (no reload needed)
4. Agent ID remains stable (from identity store)

## Acceptance Criteria

- [ ] Agent automatically reconnects after server restart
- [ ] Exponential backoff: 1s, 2s, 4s, 8s, ... up to 60s
- [ ] Jitter applied to prevent thundering herd
- [ ] `stop()` / SIGTERM cleanly interrupts reconnection loop
- [ ] Backoff resets after successful connection
- [ ] Metric: `yuzu_agent_reconnections_total` counter
- [ ] Log messages distinguish between clean shutdown and connection loss
