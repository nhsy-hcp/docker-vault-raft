#!/usr/bin/env bash
set -euo pipefail

# cluster formation testing script
# tests vault cluster formation and raft consensus

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# export vault configuration for tls
export VAULT_CACERT="${PROJECT_ROOT}/certs/ca/ca.crt"

# load vault token from vault-init.json if available
if [ -f "${PROJECT_ROOT}/vault-init.json" ]; then
  export VAULT_TOKEN=$(jq -r ".root_token" "${PROJECT_ROOT}/vault-init.json")
elif [ -f "${PROJECT_ROOT}/.env" ]; then
  # fallback to .env file
  export $(grep -v '^#' "${PROJECT_ROOT}/.env" | grep VAULT_TOKEN | xargs)
fi

echo "testing vault cluster formation..."
echo ""

# vault addresses
VAULT_ADDRS=(
  "https://localhost:8201"
  "https://localhost:8202"
  "https://localhost:8203"
)

# test 1: check all nodes are running and unsealed
echo "=== test 1: node status ==="
all_unsealed=true
for VAULT_ADDR in "${VAULT_ADDRS[@]}"; do
  export VAULT_ADDR
  echo "checking ${VAULT_ADDR}..."

  if vault status 2>/dev/null | grep -q "Sealed.*false"; then
    echo "  ✓ unsealed and accessible"
  else
    echo "  ✗ sealed or not accessible"
    all_unsealed=false
  fi
done
echo ""

if [ "${all_unsealed}" = false ]; then
  echo "⚠ some nodes are sealed. unseal all nodes first: task vault:unseal"
  exit 1
fi

# test 2: check raft cluster formation
echo "=== test 2: raft cluster ==="
export VAULT_ADDR="https://localhost:8201"

# debug: check if token is set
if [ -z "${VAULT_TOKEN}" ]; then
  echo "⚠ VAULT_TOKEN not set"
fi

# get raft peers
RAFT_OUTPUT=$(vault operator raft list-peers 2>&1)
RAFT_EXIT_CODE=$?

if [ $RAFT_EXIT_CODE -ne 0 ]; then
  echo "✗ raft cluster not formed (vault command failed)"
  echo "  error: ${RAFT_OUTPUT}"
  exit 1
fi

if ! echo "${RAFT_OUTPUT}" | grep -qi "voter\|Voter"; then
  echo "✗ raft cluster not formed"
  echo "  output: ${RAFT_OUTPUT}"
  exit 1
fi

PEER_COUNT=$(vault operator raft list-peers 2>/dev/null | grep -c "voter" || echo 0)
if [ "${PEER_COUNT}" -eq 3 ]; then
  echo "✓ raft cluster formed with ${PEER_COUNT} peers"
else
  echo "⚠ expected 3 peers, found ${PEER_COUNT}"
fi

echo ""
vault operator raft list-peers
echo ""

# test 3: identify leader
echo "=== test 3: leader election ==="
leader_found=false
for VAULT_ADDR in "${VAULT_ADDRS[@]}"; do
  export VAULT_ADDR

  if vault status 2>/dev/null | grep -q "HA Mode.*active"; then
    echo "✓ leader found at ${VAULT_ADDR}"
    leader_found=true
    break
  fi
done

if [ "${leader_found}" = false ]; then
  echo "✗ no leader found"
  exit 1
fi

echo ""
echo "cluster formation test complete"
