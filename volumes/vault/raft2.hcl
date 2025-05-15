ui                = true
disable_mlock     = true
default_lease_ttl = "1h"
max_lease_ttl     = "24h"

api_addr          = "http://docker-vault-raft-2:8202"
cluster_addr      = "http://docker-vault-raft-2:8302"

storage "raft" {
  path = "/vault/file"
  node_id = "docker-vault-raft-2"
  retry_join {
    leader_api_addr = "http://docker-vault-raft-1:8201"
  }
  retry_join {
    leader_api_addr = "http://docker-vault-raft-2:8202"
  }
  retry_join {
    leader_api_addr = "http://docker-vault-raft-3:8203"
  }
}

listener "tcp" {
  address         = "0.0.0.0:8202"
  cluster_address = "0.0.0.0:8302"
  tls_disable   = "1"
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
