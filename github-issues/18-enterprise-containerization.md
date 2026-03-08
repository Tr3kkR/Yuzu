---
title: "[P2/ENT] Add Docker images, Compose, and Kubernetes manifests"
labels: enhancement, enterprise, P2, devops
assignees: ""
---

## Summary

There are no container images, Docker Compose files, or Kubernetes manifests. Deploying Yuzu requires building from source and manually configuring services. Enterprise customers expect container-ready deployments.

## Deliverables

### 1. Dockerfiles

```dockerfile
# server/Dockerfile
FROM ubuntu:24.04 AS runtime
RUN useradd -r -s /usr/sbin/nologin yuzu
COPY --from=builder /build/yuzu-server /usr/local/bin/
USER yuzu
EXPOSE 50051 50052 8080
ENTRYPOINT ["yuzu-server"]
```

Multi-stage build: builder stage compiles from source, runtime stage is minimal.

Separate Dockerfiles for:
- `docker/server.Dockerfile`
- `docker/agent.Dockerfile`

### 2. Docker Compose

```yaml
# docker-compose.yml
services:
  server:
    build: { context: ., dockerfile: docker/server.Dockerfile }
    ports: ["50051:50051", "8080:8080"]
    volumes:
      - ./certs:/etc/yuzu/certs:ro
    environment:
      YUZU_SERVER_CERT: /etc/yuzu/certs/server.pem
      YUZU_SERVER_KEY: /etc/yuzu/certs/server-key.pem
      YUZU_CA_CERT: /etc/yuzu/certs/ca.pem
      YUZU_HTTP_API_KEY_FILE: /run/secrets/api_key
    secrets: [api_key]

  agent:
    build: { context: ., dockerfile: docker/agent.Dockerfile }
    depends_on: [server]
    volumes:
      - ./certs:/etc/yuzu/certs:ro
      - ./plugins:/opt/yuzu/plugins:ro
    environment:
      YUZU_SERVER: server:50051
```

### 3. Kubernetes manifests

- `deploy/k8s/server-deployment.yaml`
- `deploy/k8s/server-service.yaml`
- `deploy/k8s/agent-daemonset.yaml`
- `deploy/k8s/configmap.yaml`
- `deploy/k8s/secrets.yaml` (template)
- `deploy/k8s/namespace.yaml`

### 4. Helm chart (stretch goal)

- `deploy/helm/yuzu/` — parameterized chart for server + agent

## Security Considerations

- Run as non-root user in containers
- Read-only filesystem where possible
- Drop all capabilities except needed ones
- Use `securityContext` in K8s manifests
- Support Docker secrets and K8s secrets for credentials
- Health check endpoints for liveness/readiness probes

## Acceptance Criteria

- [ ] Multi-stage Dockerfiles for server and agent
- [ ] Docker Compose with TLS and secrets support
- [ ] Kubernetes manifests for server Deployment + agent DaemonSet
- [ ] CI builds and pushes container images (GHCR)
- [ ] Images scanned with Trivy or Grype in CI
- [ ] README with deployment quickstart
