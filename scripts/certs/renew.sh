#!/usr/bin/env bash
set -euo pipefail

# certificate renewal script
# checks certificate expiry and renews certificates that are expiring soon

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CERTS_DIR="${PROJECT_ROOT}/certs"
CA_DIR="${CERTS_DIR}/ca"

# threshold in days for renewal warning
RENEWAL_THRESHOLD=${RENEWAL_THRESHOLD:-90}

echo "checking certificate expiry..."
echo "renewal threshold: ${RENEWAL_THRESHOLD} days"
echo ""

# function to check certificate expiry
check_expiry() {
  local cert_file=$1
  local cert_name=$2

  if [ ! -f "${cert_file}" ]; then
    echo "  ✗ certificate not found: ${cert_file}"
    return 1
  fi

  # get certificate expiry date
  local expiry_date=$(openssl x509 -in "${cert_file}" -noout -enddate | cut -d= -f2)
  local expiry_epoch=$(date -j -f "%b %d %T %Y %Z" "${expiry_date}" "+%s")
  local current_epoch=$(date "+%s")
  local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))

  if [ ${days_until_expiry} -lt 0 ]; then
    echo "  ✗ ${cert_name}: expired ${days_until_expiry#-} days ago"
    return 1
  elif [ ${days_until_expiry} -lt ${RENEWAL_THRESHOLD} ]; then
    echo "  ⚠ ${cert_name}: expires in ${days_until_expiry} days (renewal recommended)"
    return 2
  else
    echo "  ✓ ${cert_name}: expires in ${days_until_expiry} days"
    return 0
  fi
}

needs_renewal=false

# check ca certificate
echo "checking root ca..."
if ! check_expiry "${CA_DIR}/ca.crt" "root ca"; then
  needs_renewal=true
fi
echo ""

# check vault node certificates
for NODE in vault-1 vault-2 vault-3; do
  NODE_DIR="${CERTS_DIR}/${NODE}"
  echo "checking ${NODE}..."

  if ! check_expiry "${NODE_DIR}/${NODE}.crt" "${NODE}"; then
    needs_renewal=true
  fi

  echo ""
done

if [ "${needs_renewal}" = true ]; then
  echo "certificates need renewal"
  echo ""
  read -p "renew certificates now? (y/N): " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "renewing server certificates..."
    bash "${SCRIPT_DIR}/generate-server.sh"
    echo ""
    echo "certificates renewed successfully"
    echo "restart vault cluster to apply changes: task restart"
  fi
else
  echo "all certificates are valid"
fi
