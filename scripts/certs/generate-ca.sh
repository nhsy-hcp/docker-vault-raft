#!/usr/bin/env bash
set -euo pipefail

# root ca generation script
# generates a self-signed root certificate authority

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CERTS_DIR="${PROJECT_ROOT}/certs"
CA_DIR="${CERTS_DIR}/ca"

echo "generating root ca..."

# check if ca already exists
if [ -f "${CA_DIR}/ca.key" ]; then
  echo "warning: ca private key already exists at ${CA_DIR}/ca.key"
  read -p "overwrite? (y/N): " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "ca generation cancelled"
    exit 0
  fi
fi

# generate ca private key (4096-bit rsa)
echo "generating ca private key..."
openssl genrsa -out "${CA_DIR}/ca.key" 4096

# generate self-signed ca certificate (valid for 10 years)
echo "generating ca certificate..."
openssl req -x509 -new -nodes \
  -key "${CA_DIR}/ca.key" \
  -sha256 -days 3650 \
  -out "${CA_DIR}/ca.crt" \
  -subj "/CN=Vault Root CA"

# set appropriate permissions
chmod 600 "${CA_DIR}/ca.key"
chmod 644 "${CA_DIR}/ca.crt"

echo "root ca generated successfully"
echo ""
echo "files created:"
echo "  ca private key: ${CA_DIR}/ca.key (permissions: 600)"
echo "  ca certificate: ${CA_DIR}/ca.crt (permissions: 644)"
echo ""
echo "certificate details:"
openssl x509 -in "${CA_DIR}/ca.crt" -noout -subject -issuer -dates
