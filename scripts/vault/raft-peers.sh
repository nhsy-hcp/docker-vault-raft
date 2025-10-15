#!/usr/bin/env bash
set -euo pipefail

# vault raft peers script
# displays raft cluster peer information

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# export vault configuration for tls
export VAULT_ADDR="https://localhost:8200"
export VAULT_CACERT="${PROJECT_ROOT}/certs/ca/ca.crt"

# load vault token from .env if available
if [ -f "${PROJECT_ROOT}/.env" ]; then
  export $(grep -v '^#' "${PROJECT_ROOT}/.env" | grep VAULT_TOKEN | xargs)
fi

echo "checking raft cluster peers..."
echo ""

# check if vault is initialized and unsealed
if ! vault status 2>/dev/null | grep -q "Sealed.*false"; then
  echo "error: vault is not unsealed"
  echo "unseal vault first: task vault:unseal"
  exit 1
fi

echo "=== raft peer list ==="
vault operator raft list-peers
