# Certificate Renewal

## Monitoring Certificate Expiry

### Manual Check

```bash
openssl x509 -enddate -noout -in /etc/yuzu/certs/server.crt
# Output: notAfter=Mar 21 00:00:00 2027 GMT
```

### Prometheus Alert Rule

Add to your Prometheus alert configuration:

```yaml
groups:
  - name: yuzu-tls
    rules:
      - alert: YuzuCertExpiringSoon
        expr: probe_ssl_earliest_cert_expiry - time() < 30 * 24 * 3600
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Yuzu TLS certificate expires in less than 30 days"
```

### Pre-flight Script

```bash
./scripts/yuzu-preflight.sh --cert-dir /etc/yuzu/certs
```

## Server Certificate Renewal

```bash
# 1. Generate new CSR with the same key (or generate a new key)
openssl req -new -key server.key -out server-new.csr \
  -subj "/CN=yuzu-server/O=Your Org"

# 2. Sign with your CA
openssl x509 -req -in server-new.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server-new.crt -days 365 -sha256 \
  -extfile server-ext.cnf

# 3. Replace the certificate
cp server-new.crt /etc/yuzu/certs/server.crt

# 4. Restart the server
systemctl restart yuzu-server
```

**Downtime:** Brief (seconds during restart). Agents will automatically reconnect.

## Agent Certificate Renewal

### Option 1: Re-enrollment (Recommended)

```bash
# On the agent host:
# 1. Generate new agent certificate
openssl genrsa -out agent-new.key 2048
openssl req -new -key agent-new.key -out agent-new.csr \
  -subj "/CN=$(hostname)/O=Your Org"

# 2. Sign with CA (on CA host)
openssl x509 -req -in agent-new.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out agent-new.crt -days 365 -sha256

# 3. Replace and restart
cp agent-new.crt /etc/yuzu/certs/agent.crt
cp agent-new.key /etc/yuzu/certs/agent.key
systemctl restart yuzu-agent
```

### Option 2: Windows Certificate Store

If the agent uses the Windows certificate store (`--cert-store MY`), renew the certificate in the store. The agent reads the certificate on each connection attempt — **no restart needed**.

```powershell
# Import renewed certificate
Import-PfxCertificate -FilePath agent-renewed.pfx -CertStoreLocation Cert:\LocalMachine\My
# Remove old certificate
Remove-Item Cert:\LocalMachine\My\OLD_THUMBPRINT
```

### Rolling Update for Large Fleets

1. Generate new certificates for a batch (10-20%) of agents
2. Distribute via content staging or configuration management (Ansible, SCCM)
3. Restart agents in the batch
4. Monitor dashboard for reconnection
5. Repeat for next batch

## CA Rotation

When the CA certificate itself expires:

1. **Generate new CA** with a long validity (10 years)
2. **Cross-sign**: Sign the new CA with the old CA to create a trust chain
3. **Update server**: Add both old and new CA to `--ca-cert` (concatenated PEM)
4. **Issue new agent certs** signed by the new CA
5. **Roll out** agent certs in batches
6. **Remove old CA** from server after all agents are updated

## Automated Renewal with ACME

For the HTTPS dashboard certificate (not gRPC mTLS), use certbot:

```bash
certbot certonly --standalone -d yuzu.example.com \
  --deploy-hook "systemctl restart yuzu-server"
```

Configure the server to use the ACME certificate:
```bash
yuzu-server --https --https-cert /etc/letsencrypt/live/yuzu.example.com/fullchain.pem \
  --https-key /etc/letsencrypt/live/yuzu.example.com/privkey.pem
```
