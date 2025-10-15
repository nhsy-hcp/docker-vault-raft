#!/usr/bin/env bash
set -euo pipefail

# vault configuration script
# configures audit logging, quotas, and token lease ttls

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# export vault configuration for tls
export VAULT_ADDR="https://localhost:8201"
export VAULT_CACERT="${PROJECT_ROOT}/certs/ca/ca.crt"

# source .env to get vault_token
if [ -f "${PROJECT_ROOT}/.env" ]; then
  set -a
  source "${PROJECT_ROOT}/.env"
  set +a
fi

echo "configuring vault..."
echo "vault address: ${VAULT_ADDR}"
echo ""

# check if vault is initialized and unsealed
if ! vault status 2>/dev/null | grep -q "Sealed.*false"; then
  echo "error: vault is not initialized or is sealed"
  echo "run: task vault:init && task vault:unseal"
  exit 1
fi

# check if vault token is set
if [ -z "${VAULT_TOKEN:-}" ]; then
  echo "error: VAULT_TOKEN not set in .env"
  echo "run: task vault:init to generate root token"
  exit 1
fi

# enable audit logging to stdout
echo "enabling audit logging to stdout..."
vault audit enable -path="audit_stdout" file file_path=stdout || true
echo "  ✓ audit logging configured"
echo ""

# configure rate limit audit logging
echo "configuring rate limit audit logging..."
vault write sys/quotas/config enable_rate_limit_audit_logging=true
echo "  ✓ rate limit audit logging enabled"
echo ""

# tune token auth lease ttls
echo "configuring token auth lease ttls..."
vault write sys/auth/token/tune max_lease_ttl=30d
vault write sys/auth/token/tune default_lease_ttl=7d
echo "  ✓ max lease ttl: 30d"
echo "  ✓ default lease ttl: 7d"
echo ""

# enable kv v2 secrets engine
echo "enabling kv v2 secrets engine at secrets/..."
vault secrets enable -path=secret -version=2 kv || true
echo "  ✓ kv v2 secrets engine enabled at secrets/"
echo ""

echo "vault configuration complete"
