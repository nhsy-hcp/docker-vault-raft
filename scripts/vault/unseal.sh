#!/usr/bin/env bash
set -euo pipefail

# vault unseal script
# unseals all vault nodes using keys from vault-init.json

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# check if vault-init.json exists
if [ ! -f "${PROJECT_ROOT}/vault-init.json" ]; then
  echo "error: vault-init.json not found"
  echo "initialize vault first: task vault:init"
  exit 1
fi

# export vault ca cert
export VAULT_CACERT="${PROJECT_ROOT}/certs/ca/ca.crt"

# vault addresses
VAULT_ADDRS=(
  "https://localhost:8201"
  "https://localhost:8202"
  "https://localhost:8203"
)

echo "unsealing vault nodes..."
echo ""

# unseal each vault node
for VAULT_ADDR in "${VAULT_ADDRS[@]}"; do
  export VAULT_ADDR

  echo "unsealing ${VAULT_ADDR}..."

  # check if already unsealed
  if vault status 2>/dev/null | grep -q "Sealed.*false"; then
    echo "  already unsealed"
    echo ""
    continue
  fi

  # unseal with three keys
  for i in 0 1 2; do
    UNSEAL_KEY=$(jq -r ".unseal_keys_b64[${i}]" "${PROJECT_ROOT}/vault-init.json")
    vault operator unseal "${UNSEAL_KEY}" >/dev/null 2>&1 || true
  done
  sleep 5
  # check status
  if vault status 2>/dev/null | grep -q "Sealed.*false"; then
    echo "  ✓ unsealed successfully"
  else
    echo "  ✗ failed to unseal"
  fi
  echo ""
done

echo "vault unseal complete"
echo ""
echo "check status: task vault:status"
