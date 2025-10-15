#!/usr/bin/env bash
set -euo pipefail

# certificate verification script
# verifies certificate chain and displays certificate details

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CERTS_DIR="${PROJECT_ROOT}/certs"
CA_DIR="${CERTS_DIR}/ca"

echo "verifying certificates..."
echo ""

# check if ca exists
if [ ! -f "${CA_DIR}/ca.crt" ]; then
  echo "error: root ca not found"
  exit 1
fi

# verify ca certificate
echo "=== root ca certificate ==="
openssl x509 -in "${CA_DIR}/ca.crt" -noout -subject -issuer -dates -fingerprint
echo ""

# verify each vault node certificate
for NODE in vault-1 vault-2 vault-3; do
  NODE_DIR="${CERTS_DIR}/${NODE}"

  if [ ! -f "${NODE_DIR}/${NODE}.crt" ]; then
    echo "warning: certificate not found for ${NODE}"
    continue
  fi

  echo "=== ${NODE} certificate ==="

  # verify certificate chain
  echo "verifying certificate chain..."
  if openssl verify -CAfile "${CA_DIR}/ca.crt" "${NODE_DIR}/${NODE}.crt"; then
    echo "✓ certificate chain valid"
  else
    echo "✗ certificate chain invalid"
    exit 1
  fi

  echo ""
  echo "certificate details:"
  openssl x509 -in "${NODE_DIR}/${NODE}.crt" -noout \
    -subject -issuer -dates -fingerprint

  echo ""
  echo "subject alternative names:"
  openssl x509 -in "${NODE_DIR}/${NODE}.crt" -noout -text | \
    grep -A1 "Subject Alternative Name" || echo "  none found"

  echo ""
  echo "key usage:"
  openssl x509 -in "${NODE_DIR}/${NODE}.crt" -noout -text | \
    grep -A1 "Key Usage" || echo "  none found"

  echo ""
done

echo "certificate verification complete"
