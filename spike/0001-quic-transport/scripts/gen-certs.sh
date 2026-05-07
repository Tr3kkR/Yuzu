#!/usr/bin/env bash
# Generate a self-signed CA + server cert pair for the spike.
# Throwaway material; not committed to the repo.
#
# Output:
#   certs/ca.key, ca.crt           — root CA
#   certs/server.key, server.crt   — server leaf signed by the CA
#
# The Erlang client trusts ca.crt; the C++ server presents server.crt.

set -euo pipefail

# Restrict private-key files to the running user. Default umask 022 leaves
# `*.key` world-readable; on a multi-user box that is a real exposure for
# anyone who happens to clone the spike. Throwaway material or not, the
# habit matters (governance round 5 sec-2).
umask 0077

# Reminder for anyone tempted to lift the cert config into production:
# CN=localhost + EKU serverAuth+clientAuth + 30-day lifetime is a
# DEVELOPMENT cert. The production transport's cert lifecycle is
# governed by Workstream B (cert_lifecycle_policy_url in Credentials);
# do NOT copy this script into a production install path.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTS="$HERE/certs"
mkdir -p "$CERTS"
cd "$CERTS"

if [[ -f server.crt && -f server.key && -f ca.crt ]]; then
    echo "[gen-certs] already present, skipping"
    openssl x509 -in server.crt -noout -fingerprint -sha256
    exit 0
fi

# CA
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 30 \
    -subj "/CN=yuzu-spike-CA" -out ca.crt

# Server leaf
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=localhost" -out server.csr

cat > ext.cnf <<'EOF'
basicConstraints = CA:FALSE
subjectAltName = DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth,clientAuth
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 30 -sha256 -extfile ext.cnf -out server.crt

rm -f server.csr ext.cnf ca.srl

echo "[gen-certs] done"
openssl x509 -in server.crt -noout -fingerprint -sha256
