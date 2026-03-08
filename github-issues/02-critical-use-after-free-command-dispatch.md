---
title: "[P0/CRITICAL] Fix use-after-free risk in agent command dispatch"
labels: security, bug, P0
assignees: ""
---

## Summary

In `agent.cpp`, background command execution threads capture a raw pointer to the gRPC stream (`raw_stream`), but the owning `unique_ptr<ClientReaderWriter>` may be destroyed before all threads complete their final `Write()` calls. This creates a use-after-free condition under specific timing.

## Affected Files

- `agents/core/src/agent.cpp` (lines 287-377)

## Root Cause

```cpp
auto* raw_stream = stream.get();  // line 287 — raw pointer extracted
std::thread exec_thread([this, target, cmd, raw_stream]() {
    // ... uses raw_stream at lines 328, 345 ...
});
```

The `stream` object is scoped to the block starting at line 241. Background threads are joined at lines 372-377 after `shutdown_plugins`, but `shutdown()` may return before threads finish their final `Write()` calls. If the `Read()` loop at line 356 exits (e.g., server disconnect), `stream` goes out of scope while exec threads may still be writing.

## Recommended Fix

**Option A (preferred):** Use `shared_ptr` for stream ownership:
```cpp
auto stream = std::shared_ptr<grpc::ClientReaderWriter<pb::CommandResponse, pb::CommandRequest>>(
    stub_->Subscribe(&context).release());

// Each worker thread captures shared_ptr copy
worker_threads_.emplace_back([this, stream, target, cmd]() {
    // stream is guaranteed alive while thread holds shared_ptr
});
```

**Option B:** Join all exec threads before stream destruction:
```cpp
// After Read() loop exits, join all threads BEFORE stream goes out of scope
for (auto& t : worker_threads_) {
    if (t.joinable()) t.join();
}
worker_threads_.clear();
// Now stream can safely be destroyed
```

## Acceptance Criteria

- [ ] No raw pointer to gRPC stream is captured by background threads
- [ ] Stream lifetime is guaranteed to exceed all worker thread lifetimes
- [ ] ThreadSanitizer (`-DYUZU_ENABLE_TSAN=ON`) reports no data races in command dispatch
- [ ] AddressSanitizer (`-DYUZU_ENABLE_ASAN=ON`) reports no use-after-free

## References

- SECURITY_REVIEW.md Section 1
