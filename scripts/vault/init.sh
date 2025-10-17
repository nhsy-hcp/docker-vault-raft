#!/usr/bin/env bash
set -euo pipefail

# vault initialization script
# initializes the first vault node and saves unseal keys

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# export vault configuration for tls
export VAULT_ADDR="https://localhost:8201"
export VAULT_CACERT="${PROJECT_ROOT}/certs/ca/ca.crt"

echo "initializing vault..."
echo "vault address: ${VAULT_ADDR}"
echo ""

# check if vault is already initialized
if vault status 2>/dev/null | grep -q "Initialized.*true"; then
  echo "vault is already initialized"
  exit 0
fi

# initialize vault
echo "initializing vault with 5 key shares and threshold of 3..."
vault operator init \
  -key-shares=5 \
  -key-threshold=3 \
  -format=json | tee vault-init.json

echo ""
echo "vault initialized successfully"
echo ""
echo "unseal keys and root token saved to: vault-init.json"
echo ""

# extract root token and update .env file
ROOT_TOKEN=$(jq -r '.root_token' vault-init.json)
if [ -f "${PROJECT_ROOT}/.env" ]; then
  if grep -q "^VAULT_TOKEN=" "${PROJECT_ROOT}/.env" || grep -q "^export VAULT_TOKEN=" "${PROJECT_ROOT}/.env"; then
    # remove any existing VAULT_TOKEN lines (with or without export)
    sed -i.bak "/^export VAULT_TOKEN=/d; /^VAULT_TOKEN=/d" "${PROJECT_ROOT}/.env"
    rm -f "${PROJECT_ROOT}/.env.bak"
  fi
  # add the token with export prefix
  echo "export VAULT_TOKEN=${ROOT_TOKEN}" >> "${PROJECT_ROOT}/.env"
  echo "root token added to .env file"
fi

echo ""
echo "next steps:"
echo "  1. unseal all vault nodes: task vault:unseal"
echo "  2. check cluster status: task vault:status"
echo "  3. verify raft peers: task vault:raft"
echo ""