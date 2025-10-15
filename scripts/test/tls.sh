#!/usr/bin/env bash
set -euo pipefail

# tls connection testing script
# tests tls connectivity to all vault nodes

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CA_CERT="${PROJECT_ROOT}/certs/ca/ca.crt"

echo "testing tls connections..."
echo ""

# check if ca cert exists
if [ ! -f "${CA_CERT}" ]; then
  echo "error: ca certificate not found at ${CA_CERT}"
  echo "generate certificates first: task certs:server"
  exit 1
fi

# test endpoints
ENDPOINTS=(
  "https://localhost:8201"
  "https://localhost:8202"
  "https://localhost:8203"
  "https://localhost:8200"
)

# test direct vault nodes
for ENDPOINT in "${ENDPOINTS[@]}"; do
  echo "testing ${ENDPOINT}..."

  # test tls handshake with openssl
  echo "  openssl s_client test..."
  if echo "Q" | timeout 5 openssl s_client -connect "${ENDPOINT#https://}" \
    -CAfile "${CA_CERT}" -verify_return_error >/dev/null 2>&1; then
    echo "    ✓ tls handshake successful"
  else
    echo "    ✗ tls handshake failed"
  fi

  # test http health endpoint with curl
  echo "  curl health check..."
  if curl -s --cacert "${CA_CERT}" "${ENDPOINT}/v1/sys/health" >/dev/null 2>&1; then
    echo "    ✓ health endpoint accessible"
  else
    echo "    ⚠ health endpoint not accessible (vault may be sealed)"
  fi

  echo ""
done

echo "tls connection test complete"
