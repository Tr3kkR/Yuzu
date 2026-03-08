---
title: "[P2/ENT] Add systemd service units and graceful drain"
labels: enhancement, enterprise, P2, devops
assignees: ""
---

## Summary

There are no systemd service units, no graceful connection draining, and no process management integration. Enterprise Linux deployments need proper service management.

## Deliverables

### 1. Systemd service units

```ini
# deploy/systemd/yuzu-server.service
[Unit]
Description=Yuzu Server
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=yuzu
Group=yuzu
ExecStart=/usr/local/bin/yuzu-server --config /etc/yuzu/server.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/yuzu /var/lib/yuzu
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

```ini
# deploy/systemd/yuzu-agent.service
[Unit]
Description=Yuzu Agent
After=network-online.target

[Service]
Type=notify
User=yuzu
Group=yuzu
ExecStart=/usr/local/bin/yuzu-agent --config /etc/yuzu/agent.toml
Restart=always
RestartSec=5
ProtectSystem=strict
ReadWritePaths=/var/lib/yuzu
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

### 2. Graceful drain

On SIGTERM/SIGINT:
1. Stop accepting new agent registrations
2. Stop accepting new commands
3. Wait for in-flight commands to complete (with timeout)
4. Send disconnect notification to agents
5. Close gRPC streams
6. Exit cleanly

```cpp
void Server::stop() {
    spdlog::info("Initiating graceful shutdown...");
    accepting_new_ = false;

    // Wait for in-flight commands (max 30s)
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (has_inflight_commands() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Shutdown gRPC server with deadline
    grpc_server_->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
    web_server_->stop();
}
```

### 3. sd_notify integration

For `Type=notify` systemd integration:
```cpp
#include <systemd/sd-daemon.h>

// After server is fully started:
sd_notify(0, "READY=1");

// On reload:
sd_notify(0, "RELOADING=1");

// On shutdown:
sd_notify(0, "STOPPING=1");
```

## Acceptance Criteria

- [ ] systemd service units for server and agent
- [ ] `Type=notify` with sd_notify integration
- [ ] Graceful drain waits for in-flight commands
- [ ] `ExecReload` triggers certificate/config reload
- [ ] Security hardening directives (ProtectSystem, NoNewPrivileges, etc.)
- [ ] Installation instructions for service setup
- [ ] `make install` target installs service units
