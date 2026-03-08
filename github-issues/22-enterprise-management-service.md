---
title: "[P2/ENT] Implement ManagementService gRPC API"
labels: enhancement, enterprise, P2
assignees: ""
---

## Summary

`ManagementServiceImpl` is a placeholder with no implementation. The management gRPC API (`ListAgents`, `GetAgent`, `SendCommand`, `WatchEvents`, `QueryInventory`) exists only as proto definitions. This API is needed for programmatic integrations, CLI tools, and enterprise orchestration.

## Affected Files

- `server/core/src/server.cpp` (lines 575-578) — placeholder class
- `proto/yuzu/server/v1/management.proto` — service definition
- `server/core/include/yuzu/server/server.hpp` — Config (management_address)

## Current State

```cpp
class ManagementServiceImpl : public ::yuzu::server::v1::ManagementService::Service {
public:
    // Placeholder.
};
```

The management listener is already configured on `0.0.0.0:50052` with separate TLS credentials, but serves no actual RPCs.

## Implementation Plan

### ListAgents / GetAgent

Delegate to `AgentRegistry`:
```cpp
grpc::Status ListAgents(grpc::ServerContext* ctx,
    const ListAgentsRequest* req, ListAgentsResponse* resp) override {
    auto agents = registry_.list_agents();
    for (const auto& a : agents) {
        auto* agent = resp->add_agents();
        agent->set_agent_id(a.agent_id);
        agent->set_hostname(a.hostname);
        // ...
    }
    return grpc::Status::OK;
}
```

### SendCommand

Reuse the same command dispatch logic as `/api/command` but via gRPC:
```cpp
grpc::Status SendCommand(grpc::ServerContext* ctx,
    const SendCommandRequest* req,
    grpc::ServerWriter<SendCommandResponse>* writer) override {
    // Validate auth via metadata
    // Dispatch command
    // Stream responses back
}
```

### WatchEvents

Bridge the SSE event bus to a gRPC server stream:
```cpp
grpc::Status WatchEvents(grpc::ServerContext* ctx,
    const WatchEventsRequest* req,
    grpc::ServerWriter<AgentEvent>* writer) override {
    auto sub_id = event_bus_.subscribe([writer](const SseEvent& ev) {
        AgentEvent agent_event;
        // ... convert ...
        writer->Write(agent_event);
    });
    // Block until client disconnects
    // Unsubscribe on exit
}
```

## Acceptance Criteria

- [ ] All 5 RPCs implemented (ListAgents, GetAgent, SendCommand, WatchEvents, QueryInventory)
- [ ] Management listener uses separate TLS credentials
- [ ] RBAC enforced on management RPCs
- [ ] Unit tests for each RPC
- [ ] CLI client tool (stretch goal): `yuzu-ctl list-agents`, `yuzu-ctl send-command`

## References

- `proto/yuzu/server/v1/management.proto`
- SECURITY_REVIEW.md Section 5
