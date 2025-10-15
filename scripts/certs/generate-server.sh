#!/usr/bin/env bash
set -euo pipefail

# server certificate generation script
# generates tls certificates for all vault nodes

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CERTS_DIR="${PROJECT_ROOT}/certs"
CA_DIR="${CERTS_DIR}/ca"

echo "generating server certificates..."

# check if ca exists
if [ ! -f "${CA_DIR}/ca.key" ] || [ ! -f "${CA_DIR}/ca.crt" ]; then
  echo "error: root ca not found. run 'task certs:ca' first"
  exit 1
fi

# generate certificates for each vault node
for NODE in vault-1 vault-2 vault-3; do
  NODE_DIR="${CERTS_DIR}/${NODE}"
  echo ""
  echo "generating certificate for ${NODE}..."

  # check if certificate already exists
  if [ -f "${NODE_DIR}/${NODE}.key" ]; then
    echo "warning: certificate already exists for ${NODE}"
    read -p "overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      echo "skipping ${NODE}"
      continue
    fi
  fi

  # generate private key
  echo "  generating private key..."
  openssl genrsa -out "${NODE_DIR}/${NODE}.key" 4096

  # create openssl config for this node
  cat > "${NODE_DIR}/${NODE}.cnf" <<EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = ${NODE}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${NODE}
DNS.2 = localhost
DNS.3 = vault
IP.1 = 127.0.0.1
EOF

  # generate certificate signing request
  echo "  generating csr..."
  openssl req -new -key "${NODE_DIR}/${NODE}.key" \
    -out "${NODE_DIR}/${NODE}.csr" \
    -config "${NODE_DIR}/${NODE}.cnf"

  # sign certificate with ca
  echo "  signing certificate..."
  openssl x509 -req -in "${NODE_DIR}/${NODE}.csr" \
    -CA "${CA_DIR}/ca.crt" \
    -CAkey "${CA_DIR}/ca.key" \
    -CAcreateserial \
    -out "${NODE_DIR}/${NODE}.crt" \
    -days 365 \
    -sha256 \
    -extensions v3_req \
    -extfile "${NODE_DIR}/${NODE}.cnf"

  # set appropriate permissions
  chmod 600 "${NODE_DIR}/${NODE}.key"
  chmod 644 "${NODE_DIR}/${NODE}.crt"

  echo "  certificate generated successfully for ${NODE}"
  echo "    private key: ${NODE_DIR}/${NODE}.key (permissions: 600)"
  echo "    certificate: ${NODE_DIR}/${NODE}.crt (permissions: 644)"
done

echo ""
echo "all server certificates generated successfully"
echo ""
echo "to verify certificates, run: task certs:verify"
