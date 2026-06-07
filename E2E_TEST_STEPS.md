# E2E Test Steps for Hardened vuln_scan Plugin

## Prerequisites
- ✅ Server running at http://localhost:8092
- ✅ Gateway running 
- ✅ Database initialized
- Docker image `yuzu-agent:hardened` being built

## Test Workflow

### Step 1: Verify Docker Image (After Build Completes)
```bash
docker images | grep yuzu-agent:hardened
```
Expected: Image should appear with tag `hardened`

### Step 2: Run Agent Container
```bash
docker run -d \
  --name yuzu-agent-test \
  --network bridge \
  -e YUZU_SERVER=host.docker.internal:50051 \
  yuzu-agent:hardened
```

Alternative if not on macOS, connect to Docker network directly:
```bash
docker network ls | grep yuzu
docker run -d \
  --name yuzu-agent-test \
  --network <yuzu-network-name> \
  -e YUZU_SERVER=yuzu-server:50051 \
  yuzu-agent:hardened
```

### Step 3: Wait for Agent Enrollment
```bash
# Monitor server logs for agent registration
docker logs -f yuzu-server 2>&1 | grep -i "agent\|register"
# Wait for: "AgentRegistry: agent ... registered"
```
Timeout: 30 seconds

### Step 4: Approve Agent in Dashboard
1. Open http://localhost:8092 in browser
2. Login: admin / adminpassword1
3. Navigate to: Settings → Agents
4. Find agent with ID from server logs
5. Click "Approve"
6. Verify status changes to "Active"

### Step 5: Send vuln_scan Instruction
Option A - Via REST API:
```bash
curl -s -u admin:adminpassword1 \
  -X POST http://localhost:8092/api/v1/instructions \
  -H "Content-Type: application/json" \
  -d '{
    "definition_id": "security.vuln_scan.scan",
    "scope_criteria": "all",
    "parameters": {}
  }' | jq .
```

Option B - Via Dashboard:
1. Device Management
2. Select the enrolled agent
3. Send Instruction → security.vuln_scan.scan
4. Execute

### Step 6: Verify Results
```bash
# Via API
curl -s -u admin:adminpassword1 \
  'http://localhost:8092/api/v1/responses?instruction_id=<ID>' | jq '.responses[0].findings'
```

Expected findings: Should detect real CVEs (at minimum from compilation toolchain packages like OpenSSL, curl, etc.)

### Step 7: Test kernel_scan Action
```bash
curl -s -u admin:adminpassword1 \
  -X POST http://localhost:8092/api/v1/instructions \
  -H "Content-Type: application/json" \
  -d '{
    "definition_id": "security.vuln_scan.kernel_scan",
    "scope_criteria": "all",
    "parameters": {}
  }' | jq .
```

Expected: Should detect kernel version in agent container (Linux kernel)

### Step 8: Test config_scan Action
```bash
curl -s -u admin:adminpassword1 \
  -X POST http://localhost:8092/api/v1/instructions \
  -H "Content-Type: application/json" \
  -d '{
    "definition_id": "security.vuln_scan.config_scan",
    "scope_criteria": "all",
    "parameters": {}
  }' | jq .
```

Expected: Should detect CIS Level 1 benchmark issues in container (many will fail as container is not hardened)

## Success Criteria
1. ✅ Agent enrolls automatically
2. ✅ Agent approves successfully
3. ✅ vuln_scan instruction executes without error
4. ✅ Results contain at least 2 CVEs
5. ✅ kernel_scan detects kernel version
6. ✅ config_scan reports CIS checks (some PASS, some FAIL)
7. ✅ All 3 actions (scan, kernel_scan, config_scan) return valid JSON responses

## Cleanup
```bash
docker stop yuzu-agent-test
docker rm yuzu-agent-test
```
