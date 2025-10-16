#!/usr/bin/env bash
set -euo pipefail

# failover testing script
# tests vault cluster failover by stopping the leader

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# export vault configuration for tls
export VAULT_CACERT="${PROJECT_ROOT}/certs/ca/ca.crt"

# load vault token from .env if available
if [ -f "${PROJECT_ROOT}/.env" ]; then
  export $(grep -v '^#' "${PROJECT_ROOT}/.env" | grep VAULT_TOKEN | xargs)
fi

echo "testing vault cluster failover..."
echo ""

# vault addresses
VAULT_ADDRS=(
  "https://localhost:8201"
  "https://localhost:8202"
  "https://localhost:8203"
)

# find current leader
echo "=== step 1: identify leader ==="
leader_addr=""
leader_container=""

for i in "${!VAULT_ADDRS[@]}"; do
  VAULT_ADDR="${VAULT_ADDRS[$i]}"
  export VAULT_ADDR

  if vault status 2>/dev/null | grep -q "HA Mode.*active"; then
    leader_addr="${VAULT_ADDR}"
    leader_container="vault-$((i + 1))"
    echo "current leader: ${leader_addr} (${leader_container})"
    break
  fi
done

if [ -z "${leader_addr}" ]; then
  echo "✗ no leader found"
  exit 1
fi
echo ""

# write test data before failover
echo "=== step 2: write test data ==="
export VAULT_ADDR="${leader_addr}"
TEST_PATH="secret/failover-test"
TEST_VALUE="failover-test-$(date +%s)"

echo "writing test secret..."
if vault kv put "${TEST_PATH}" value="${TEST_VALUE}" timestamp="$(date)" >/dev/null 2>&1; then
  echo "✓ test data written successfully"
else
  echo "⚠ failed to write test data (kv-v2 may not be enabled)"
fi
echo ""

# stop the leader
echo "=== step 3: stop leader ==="
echo "stopping ${leader_container}..."
docker stop "${leader_container}"
echo "waiting for new leader election..."
sleep 10
echo ""

# verify new leader
echo "=== step 4: verify new leader ==="
new_leader_addr=""
for VAULT_ADDR in "${VAULT_ADDRS[@]}"; do
  if [ "${VAULT_ADDR}" = "${leader_addr}" ]; then
    continue
  fi

  export VAULT_ADDR

  if vault status 2>/dev/null | grep -q "HA Mode.*active"; then
    new_leader_addr="${VAULT_ADDR}"
    echo "✓ new leader elected: ${new_leader_addr}"
    break
  fi
done

if [ -z "${new_leader_addr}" ]; then
  echo "✗ no new leader elected"
  docker start "${leader_container}"
  exit 1
fi
echo ""

# verify data is still accessible
echo "=== step 5: verify data accessibility ==="
export VAULT_ADDR="${new_leader_addr}"

echo "reading test secret from new leader..."
if vault kv get "${TEST_PATH}" 2>/dev/null | grep -q "${TEST_VALUE}"; then
  echo "✓ data accessible from new leader"
else
  echo "⚠ data not accessible"
fi
echo ""

# restart original leader
echo "=== step 6: restart original leader ==="
echo "restarting ${leader_container}..."
docker start "${leader_container}"
echo "waiting for node to start..."
sleep 5

# unseal the restarted node
export VAULT_ADDR="${leader_addr}"
echo "unsealing ${leader_container}..."

INIT_FILE="${PROJECT_ROOT}/vault-init.json"
if [ ! -f "${INIT_FILE}" ]; then
  echo "✗ vault-init.json not found"
  exit 1
fi

# extract unseal keys and unseal
UNSEAL_KEYS=$(jq -r '.unseal_keys_b64[]' "${INIT_FILE}")
unseal_count=0

for key in ${UNSEAL_KEYS}; do
  if vault operator unseal "${key}" >/dev/null 2>&1; then
    unseal_count=$((unseal_count + 1))
    if [ ${unseal_count} -eq 3 ]; then
      echo "✓ node unsealed successfully"
      break
    fi
  fi
done

if [ ${unseal_count} -lt 3 ]; then
  echo "✗ failed to unseal node"
  exit 1
fi

echo "waiting for node to rejoin..."
sleep 5

# check if original leader rejoined as follower
if vault status 2>/dev/null | grep -q "HA Mode.*standby"; then
  echo "✓ original leader rejoined as standby"
else
  echo "⚠ original leader status unclear"
fi
echo ""

# verify raft peers
echo "=== step 7: verify raft peers ==="
export VAULT_ADDR="${new_leader_addr}"
vault operator raft list-peers
echo ""

echo "failover test complete"
echo ""
echo "summary:"
echo "  original leader: ${leader_addr}"
echo "  new leader: ${new_leader_addr}"
