ui                = true
disable_mlock     = true
default_lease_ttl = "1h"
max_lease_ttl     = "24h"

api_addr          = "https://{{NODE_ID}}:8200"
cluster_addr      = "https://{{NODE_ID}}:8201"

storage "raft" {
  path = "/vault/file"
  node_id = "{{NODE_ID}}"

  retry_join {
    leader_api_addr = "https://vault-1:8200"
    leader_ca_cert_file = "/vault/certs/ca.crt"
    leader_client_cert_file = "/vault/certs/{{NODE_ID}}.crt"
    leader_client_key_file = "/vault/certs/{{NODE_ID}}.key"
  }
  retry_join {
    leader_api_addr = "https://vault-2:8200"
    leader_ca_cert_file = "/vault/certs/ca.crt"
    leader_client_cert_file = "/vault/certs/{{NODE_ID}}.crt"
    leader_client_key_file = "/vault/certs/{{NODE_ID}}.key"
  }
  retry_join {
    leader_api_addr = "https://vault-3:8200"
    leader_ca_cert_file = "/vault/certs/ca.crt"
    leader_client_cert_file = "/vault/certs/{{NODE_ID}}.crt"
    leader_client_key_file = "/vault/certs/{{NODE_ID}}.key"
  }
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file   = "/vault/certs/{{NODE_ID}}.crt"
  tls_key_file    = "/vault/certs/{{NODE_ID}}.key"
  tls_client_ca_file = "/vault/certs/ca.crt"
  tls_min_version = "tls12"
  tls_cipher_suites = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
  tls_require_and_verify_client_cert = false
  telemetry {
    unauthenticated_metrics_access = true
  }
}

telemetry {
  disable_hostname = true
  prometheus_retention_time = "12h"
}

reporting {
    license {
        enabled = false
   }
}
