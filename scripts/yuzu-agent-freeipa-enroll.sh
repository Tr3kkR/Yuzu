#!/bin/bash
# yuzu-agent-freeipa-enroll.sh — Enroll a Yuzu agent using FreeIPA/certmonger
#
# This script provisions a client certificate via FreeIPA's certmonger service,
# then starts the yuzu-agent. Designed for RHEL/CentOS/Fedora systems joined
# to a FreeIPA domain.
#
# Prerequisites:
#   - Host is enrolled in FreeIPA (ipa-client-install completed)
#   - certmonger service is running (systemctl start certmonger)
#   - yuzu-agent binary is installed
#
# Usage:
#   sudo ./yuzu-agent-freeipa-enroll.sh [--server ADDRESS] [--token TOKEN]
#
# The script will:
#   1. Request a certificate from IPA CA via certmonger
#   2. Wait for the certificate to be issued
#   3. Configure yuzu-agent to use the provisioned certificate
#   4. Optionally start/enable the systemd service

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────

YUZU_CERT_DIR="/etc/yuzu"
YUZU_CERT="${YUZU_CERT_DIR}/agent.pem"
YUZU_KEY="${YUZU_CERT_DIR}/agent-key.pem"
YUZU_PRINCIPAL="yuzu-agent/$(hostname -f)"
YUZU_SERVER=""
YUZU_TOKEN=""
YUZU_ENABLE_SERVICE=false
MAX_WAIT_SECS=120

# ── Parse arguments ──────────────────────────────────────────────────────────

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --server ADDRESS    Yuzu server address (host:port)"
    echo "  --token TOKEN       Enrollment token for initial registration"
    echo "  --enable-service    Enable and start yuzu-agent systemd service"
    echo "  --cert-dir DIR      Certificate directory (default: /etc/yuzu)"
    echo "  --principal NAME    Kerberos principal (default: yuzu-agent/<fqdn>)"
    echo "  --help              Show this help"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)       YUZU_SERVER="$2"; shift 2 ;;
        --token)        YUZU_TOKEN="$2"; shift 2 ;;
        --enable-service) YUZU_ENABLE_SERVICE=true; shift ;;
        --cert-dir)     YUZU_CERT_DIR="$2"; YUZU_CERT="${YUZU_CERT_DIR}/agent.pem"; YUZU_KEY="${YUZU_CERT_DIR}/agent-key.pem"; shift 2 ;;
        --principal)    YUZU_PRINCIPAL="$2"; shift 2 ;;
        --help)         usage ;;
        *)              echo "Unknown option: $1"; usage ;;
    esac
done

# ── Preflight checks ────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (for certmonger access)."
    exit 1
fi

for cmd in ipa-getcert getcert hostname; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: Required command '$cmd' not found."
        echo "       Ensure ipa-client is installed: dnf install ipa-client"
        exit 1
    fi
done

if ! systemctl is-active --quiet certmonger; then
    echo "Starting certmonger service..."
    systemctl start certmonger
fi

# ── Ensure certificate directory ─────────────────────────────────────────────

mkdir -p "${YUZU_CERT_DIR}"
chmod 750 "${YUZU_CERT_DIR}"

# ── Check for existing valid certificate ─────────────────────────────────────

if [[ -f "${YUZU_CERT}" && -f "${YUZU_KEY}" ]]; then
    # Check if cert is still valid (not expiring within 24h)
    if openssl x509 -in "${YUZU_CERT}" -checkend 86400 -noout 2>/dev/null; then
        echo "Valid certificate already exists at ${YUZU_CERT}"
        echo "Skipping certificate request. Delete ${YUZU_CERT} to force renewal."
    else
        echo "Existing certificate is expired or expiring soon. Requesting renewal..."
        rm -f "${YUZU_CERT}" "${YUZU_KEY}"
    fi
fi

# ── Request certificate via certmonger ───────────────────────────────────────

if [[ ! -f "${YUZU_CERT}" ]]; then
    echo "Requesting certificate from IPA CA..."
    echo "  Principal: ${YUZU_PRINCIPAL}"
    echo "  Cert file: ${YUZU_CERT}"
    echo "  Key file:  ${YUZU_KEY}"

    # Add IPA service principal (may already exist)
    ipa service-add "${YUZU_PRINCIPAL}" 2>/dev/null || true

    # Request certificate using certmonger (ipa-getcert)
    ipa-getcert request \
        -K "${YUZU_PRINCIPAL}" \
        -f "${YUZU_CERT}" \
        -k "${YUZU_KEY}" \
        -N "CN=$(hostname -f)" \
        -D "$(hostname -f)" \
        -C "systemctl restart yuzu-agent" \
        -w

    echo "Certificate request submitted. Waiting for issuance..."

    # Wait for certificate to be issued
    elapsed=0
    while [[ $elapsed -lt $MAX_WAIT_SECS ]]; do
        status=$(getcert list -f "${YUZU_CERT}" 2>/dev/null | grep "status:" | awk '{print $2}')
        case "${status}" in
            MONITORING)
                echo "Certificate issued successfully!"
                break
                ;;
            SUBMITTING|NEED_GUIDANCE|CA_UNREACHABLE)
                echo "  Status: ${status} (waiting...)"
                sleep 5
                elapsed=$((elapsed + 5))
                ;;
            *)
                echo "  Status: ${status:-unknown} (waiting...)"
                sleep 5
                elapsed=$((elapsed + 5))
                ;;
        esac
    done

    if [[ ! -f "${YUZU_CERT}" ]]; then
        echo "ERROR: Certificate was not issued within ${MAX_WAIT_SECS} seconds."
        echo "Check: getcert list -f ${YUZU_CERT}"
        exit 1
    fi

    # Set permissions (readable by yuzu-agent service user)
    chmod 644 "${YUZU_CERT}"
    chmod 600 "${YUZU_KEY}"
    echo "Certificate files ready."
fi

# ── Configure yuzu-agent ─────────────────────────────────────────────────────

YUZU_CONFIG="/etc/yuzu/yuzu-agent.cfg"

if [[ ! -f "${YUZU_CONFIG}" ]]; then
    echo "Creating agent configuration at ${YUZU_CONFIG}..."
    cat > "${YUZU_CONFIG}" << EOF
# Yuzu Agent Configuration (provisioned by freeipa-enroll)
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

server_address=${YUZU_SERVER:-server.example.com:50051}
tls_enabled=true
client_cert=${YUZU_CERT}
client_key=${YUZU_KEY}
EOF

    if [[ -n "${YUZU_TOKEN}" ]]; then
        echo "enrollment_token=${YUZU_TOKEN}" >> "${YUZU_CONFIG}"
    fi

    chmod 640 "${YUZU_CONFIG}"
    echo "Configuration written."
else
    echo "Configuration already exists at ${YUZU_CONFIG} (not overwriting)."
fi

# ── Start/enable systemd service ─────────────────────────────────────────────

if $YUZU_ENABLE_SERVICE; then
    echo "Enabling and starting yuzu-agent service..."
    systemctl enable yuzu-agent
    systemctl restart yuzu-agent
    systemctl status yuzu-agent --no-pager
fi

echo ""
echo "=== Enrollment complete ==="
echo "  Certificate: ${YUZU_CERT}"
echo "  Key:         ${YUZU_KEY}"
echo "  Config:      ${YUZU_CONFIG}"
if [[ -n "${YUZU_SERVER}" ]]; then
    echo "  Server:      ${YUZU_SERVER}"
fi
echo ""
echo "Certmonger will automatically renew this certificate before expiry."
echo "To verify: getcert list -f ${YUZU_CERT}"
