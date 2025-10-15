#!/usr/bin/env bash
set -euo pipefail

# certificate directory initialization script
# creates the directory structure for certificate storage

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CERTS_DIR="${PROJECT_ROOT}/certs"

echo "creating certificate directory structure..."

# create main certificate directory
mkdir -p "${CERTS_DIR}"

# create ca directory
mkdir -p "${CERTS_DIR}/ca"

# create vault node directories
for NODE in vault-1 vault-2 vault-3; do
  mkdir -p "${CERTS_DIR}/${NODE}"
done

echo "certificate directory structure created successfully"
echo ""
echo "structure:"
echo "  ${CERTS_DIR}/"
echo "  ├── ca/"
echo "  ├── vault-1/"
echo "  ├── vault-2/"
echo "  └── vault-3/"
