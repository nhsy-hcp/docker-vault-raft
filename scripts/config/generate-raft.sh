#!/usr/bin/env bash
set -euo pipefail

# raft configuration generation script
# generates vault raft configuration files from template

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEMPLATE_FILE="${PROJECT_ROOT}/templates/raft.tpl.hcl"
CONFIG_DIR="${PROJECT_ROOT}/configs/vault"

echo "generating vault raft configuration files from template..."

# check if template exists
if [ ! -f "${TEMPLATE_FILE}" ]; then
  echo "error: template file not found at ${TEMPLATE_FILE}"
  exit 1
fi

# create config directory if it doesn't exist
mkdir -p "${CONFIG_DIR}"

# generate configuration for each vault node
for NODE_NUM in 1 2 3; do
  NODE_ID="vault-${NODE_NUM}"
  CONFIG_FILE="${CONFIG_DIR}/${NODE_ID}.hcl"

  echo ""
  echo "generating configuration for ${NODE_ID}..."

  # check if configuration already exists
  if [ -f "${CONFIG_FILE}" ]; then
    echo "warning: configuration file already exists: ${CONFIG_FILE}"
    read -p "overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      echo "skipping ${NODE_ID}"
      continue
    fi
  fi

  # generate configuration by replacing placeholders
  sed "s/{{NODE_ID}}/${NODE_ID}/g" "${TEMPLATE_FILE}" > "${CONFIG_FILE}"

  # set appropriate permissions
  chmod 644 "${CONFIG_FILE}"

  echo "  configuration generated successfully: ${CONFIG_FILE}"
done

echo ""
echo "all vault configuration files generated successfully"
echo ""
echo "configuration files:"
echo "  ${CONFIG_DIR}/vault-1.hcl"
echo "  ${CONFIG_DIR}/vault-2.hcl"
echo "  ${CONFIG_DIR}/vault-3.hcl"
echo ""
echo "to start the cluster, run: task up"
