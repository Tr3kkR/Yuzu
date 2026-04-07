#!/bin/bash
set -euo pipefail

RUNNER_DIR="/home/runner"

# Configure the runner if not already configured
if [ ! -f "${RUNNER_DIR}/.runner" ]; then
  echo "Configuring runner..."
  ${RUNNER_DIR}/config.sh \
    --url "${RUNNER_URL}" \
    --token "${RUNNER_TOKEN}" \
    --name "${RUNNER_NAME:-yuzu-local-linux}" \
    --labels "${RUNNER_LABELS:-self-hosted,X64,Linux}" \
    --work "${RUNNER_WORKDIR:-/home/runner/_work}" \
    --unattended \
    --replace
fi

# Handle graceful shutdown
cleanup() {
  echo "Removing runner..."
  ${RUNNER_DIR}/config.sh remove --token "${RUNNER_TOKEN}" 2>/dev/null || true
}
trap cleanup SIGTERM SIGINT

# Start the runner
echo "Starting runner..."
exec ${RUNNER_DIR}/run.sh
