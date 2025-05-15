#!/usr/bin/env bash

VAULT_ADDRS=("http://127.0.0.1:8201" "http://127.0.0.1:8202" "http://127.0.0.1:8203")

for VAULT_ADDR in "${VAULT_ADDRS[@]}"; do
  export VAULT_ADDR
  echo "Checking status for $VAULT_ADDR"
  vault status
  sleep 3
  echo "Unsealing vault at $VAULT_ADDR..."
  vault operator unseal $(cat vault-init.json | jq -r '.unseal_keys_b64[0]')
  vault operator unseal $(cat vault-init.json | jq -r '.unseal_keys_b64[1]')
  vault operator unseal $(cat vault-init.json | jq -r '.unseal_keys_b64[2]')
  vault status
  export VAULT_TOKEN=$(cat vault-init.json | jq -r '.root_token')
  echo
  echo "Vault at $VAULT_ADDR is unsealed and ready to use."
  echo VAULT_ADDR: $VAULT_ADDR
  echo VAULT_TOKEN: $VAULT_TOKEN
  echo "-----------------------------"
done