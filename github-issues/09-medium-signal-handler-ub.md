---
title: "[P1/MEDIUM] Remove async-signal-unsafe calls from signal handlers"
labels: bug, P1
assignees: ""
---

## Summary

Both agent and server signal handlers call `spdlog::warn()`, which allocates memory and acquires mutexes — undefined behavior in a signal handler per POSIX. This can cause deadlocks or crashes during graceful shutdown.

## Affected Files

- `agents/core/src/main.cpp` (lines 29-31)
- `server/core/src/main.cpp` (lines 15-17)

## Root Cause

```cpp
static void on_signal(int sig) {
    spdlog::warn("Caught signal {}, shutting down...", sig);  // UB!
    if (g_agent) g_agent->stop();
}
```

## Recommended Fix

```cpp
static std::atomic<int> g_caught_signal{0};

static void on_signal(int sig) {
    g_caught_signal.store(sig, std::memory_order_relaxed);
    if (g_agent) g_agent->stop();  // atomic store + TryCancel — likely safe
}

// In main(), after run() returns:
if (auto sig = g_caught_signal.load(); sig != 0) {
    spdlog::info("Caught signal {}, shutdown complete", sig);
}
```

Also make `g_agent` / `g_server` pointer `std::atomic<Agent*>` for defensive correctness.

## Acceptance Criteria

- [ ] No `spdlog` calls in signal handlers
- [ ] Signal number logged from main thread after shutdown
- [ ] Global pointers are `std::atomic`
- [ ] TSan clean under signal delivery stress test
