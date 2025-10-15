#!/usr/bin/env bash
set -euo pipefail

# vault status script
# displays status of all vault nodes

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# export vault ca cert
export VAULT_CACERT="${PROJECT_ROOT}/certs/ca/ca.crt"

# vault addresses
VAULT_ADDRS=(
  "https://localhost:8201"
  "https://localhost:8202"
  "https://localhost:8203"
)

echo "checking vault node status..."
echo ""

# check each vault node
for VAULT_ADDR in "${VAULT_ADDRS[@]}"; do
  export VAULT_ADDR

  echo "=== ${VAULT_ADDR} ==="

  if vault status 2>/dev/null; then
    echo ""
  else
    echo "✗ unable to connect to ${VAULT_ADDR}"
    echo ""
  fi
done

echo "status check complete"
