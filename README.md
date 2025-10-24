# Vault Raft Cluster with TLS and HAProxy LB
A HashiCorp Vault Enterprise cluster with end-to-end TLS encryption, Raft consensus storage, and HAProxy load balancing.

## Features
- 3-node Vault cluster
- TLS encryption using self-signed CA certificates
- HAProxy load balancer with TLS passthrough
- Raft integrated storage
- Load testing scripts in [scripts/loadtest](scripts/loadtest) folder

## Architecture
```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENT APPLICATIONS                         │
│                         (TLS Connections)                           │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ HTTPS (TLS)
                                 ▼
                    ┌────────────────────────┐
                    │      HAProxy LB        │
                    │   (TLS Passthrough)    │
                    │    Port: 8200          │
                    │  Stats: 8080/stats     │
                    └────────┬───────────────┘
                             │
             ┌───────────────┼───────────────┐
             │               │               │
             ▼               ▼               ▼
    ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
    │   vault-1      │ │   vault-2      │ │   vault-3      │
    │   (Leader)     │ │  (Follower)    │ │  (Follower)    │
    │                │ │                │ │                │
    │  ┌──────────┐  │ │  ┌──────────┐  │ │  ┌──────────┐  │
    │  │  Vault   │  │ │  │  Vault   │  │ │  │  Vault   │  │
    │  └─────┬────┘  │ │  └─────┬────┘  │ │  └─────┬────┘  │
    │        │       │ │        │       │ │        │       │
    │  ┌─────▼────┐  │ │  ┌─────▼────┐  │ │  ┌─────▼────┐  │
    │  │   Raft   │◄─┼─┼─►│   Raft   │◄─┼─┼─►│   Raft   │  │
    │  │ Storage  │  │ │  │ Storage  │  │ │  │ Storage  │  │
    │  └──────────┘  │ │  └──────────┘  │ │  └──────────┘  │
    └────────────────┘ └────────────────┘ └────────────────┘
            │                  │                  │
            └──────────────────┼──────────────────┘
                               │
                    Raft Consensus Protocol
                    (Leader Election & Replication)

┌─────────────────────────────────────────────────────────────────────┐
│                      NETWORK & PORT MAPPING                         │
├─────────────────────────────────────────────────────────────────────┤
│  HAProxy:       localhost:8200  →  Vault LB (TLS Passthrough)       │
│  HAProxy Stats: localhost:8080  →  haproxy:8080 (HTTP)              │
│  Vault Node 1:  localhost:8201  →  vault-1:8200 (HTTPS)             │
│  Vault Node 2:  localhost:8202  →  vault-2:8200 (HTTPS)             │
│  Vault Node 3:  localhost:8203  →  vault-3:8200 (HTTPS)             │
└─────────────────────────────────────────────────────────────────────┘
```

## Prerequisites
- [Docker](https://www.docker.com/get-started)
- [Task](https://taskfile.dev)
- Vault Enterprise license

Install on macOS:
```bash
brew install go-task
```

## Quick Start
### 1. Setup Environment
```bash
# Copy environment template
cp .env.example .env

# Edit .env and add your Vault license
VAULT_LICENSE=your-license-here
```

### 2. Generate Configuration
```bash
# Generate all certificates and configuration files
task config:all
```

### 3. Start Cluster

```bash
# Start all containers
task up
```

### 4. Initialize and Unseal Vault
```bash
# Initialize Vault (first time only)
task vault:init

# Unseal all nodes
task vault:unseal
```

### 5. Verify Cluster
```bash
# Check cluster status
task vault:status

# View raft peers
task vault:raft
```

## Access Points
- **Vault LB (Leader)**: https://localhost:8200
- **Vault Node 1**: https://localhost:8201
- **Vault Node 2**: https://localhost:8202
- **Vault Node 3**: https://localhost:8203
- **HAProxy Stats**: http://localhost:8080/stats

## Common Commands
**Configuration:**
```bash
task config:all     # Generate all (certs + config)
task config:certs   # Generate certificates only
task config:raft    # Generate vault configs only
task certs:verify   # Verify certificates
task certs:renew    # Renew expiring certificates
```

**Cluster Operations:**
```bash
task up             # Start cluster
task down           # Stop cluster
task restart        # Restart cluster (auto-unseals)
task clean          # Remove containers and volumes
```

**Vault Operations:**
```bash
task vault:init     # Initialize Vault
task vault:unseal   # Unseal all nodes
task vault:status   # Check status
task vault:raft     # Show raft peers
```

**Monitoring:**
```bash
task logs           # View all logs
task logs:vault     # View Vault logs only
task logs:haproxy   # View HAProxy logs only
task health         # Health check
task metrics        # Prometheus metrics
```

**Testing:**
```bash
task test:tls       # Test TLS connections
task test:cluster   # Test cluster formation
task test:failover  # Test HA failover
task test:all       # Run all tests
```

**Utilities:**
```bash
task ui             # Open Vault UI and HAProxy stats
task shell -- vault-1   # Shell into a container
task data:df        # Check disk usage
task data:ls        # List Vault data directories
task data:destroy -- vault-1  # Destroy data for a node
```

## Load Testing

The `scripts/loadtest/generate_load.py` script generates load on your Vault cluster to test performance and validate high-availability features. It supports three modes: PKI certificate leases, AppRole token leases, and KV v2 secrets.

### Prerequisites

Create the parent namespace for load testing:
```bash
vault namespace create loadtest
```

Install Python dependencies:
```bash
pip install -r requirements.txt
```
Or use a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Setup
Configure environment variables (already set if you completed Quick Start):
```bash
source .env
```

### PKI Mode - Certificate Leases

Generate PKI certificate leases by creating namespaces, enabling PKI engines, configuring CAs, and signing certificates.

**Basic example** - Generate 1000 certificate leases (10 namespaces × 100 leases each):
```bash
python3 scripts/loadtest/generate_load.py \
  --namespaces 10 \
  pki --leases-per-namespace 100
```

**Custom TTL** - Generate leases with 30-minute TTL:
```bash
python3 scripts/loadtest/generate_load.py \
  --namespaces 5 \
  pki --leases-per-namespace 50 --ttl 30m
```

### AppRoles Mode - Token Leases

Generate AppRole authentication token leases by creating AppRole auth methods, roles, secret IDs, and performing logins.

**Basic example** - Generate 500 AppRole token leases (10 namespaces × 50 approles each):
```bash
python3 scripts/loadtest/generate_load.py \
  --namespaces 10 \
  approles --approles-per-namespace 50
```

**Custom TTLs** - Configure token TTL and max TTL:
```bash
python3 scripts/loadtest/generate_load.py \
  --namespaces 5 \
  approles --approles-per-namespace 100 \
  --approle-ttl 2h --approle-max-ttl 48h
```

### KV Mode - Key-Value Secrets

Generate KV v2 secrets by creating namespaces, enabling KV engines, and writing random secrets.

**Basic example** - Generate 1000 secrets (10 namespaces × 10 engines × 10 secrets):
```bash
python3 scripts/loadtest/generate_load.py \
  --namespaces 10 \
  kv --engines-per-namespace 10 --secrets-per-engine 10
```

**High-volume secrets** - Generate 10,000 secrets:
```bash
python3 scripts/loadtest/generate_load.py \
  --namespaces 20 \
  kv --engines-per-namespace 10 --secrets-per-engine 50
```

**Fewer engines, more secrets per engine**:
```bash
python3 scripts/loadtest/generate_load.py \
  --namespaces 5 \
  kv --engines-per-namespace 3 --secrets-per-engine 100
```

### Common Options

**Use custom parent namespace** (default: loadtest):
```bash
python3 scripts/loadtest/generate_load.py \
  --parent-namespace sandbox \
  --namespaces 20 \
  pki --leases-per-namespace 50
```

**Increase parallel workers** (default: 4):
```bash
python3 scripts/loadtest/generate_load.py \
  --workers 8 \
  --namespaces 20 \
  pki --leases-per-namespace 100
```

### Example Output

```
2025-10-17 14:30:00 - __main__ - INFO - Starting PKI load generation:
2025-10-17 14:30:00 - __main__ - INFO -   Parent namespace: loadtest
2025-10-17 14:30:00 - __main__ - INFO -   Namespaces: 10
2025-10-17 14:30:00 - __main__ - INFO -   Leases per namespace: 100
2025-10-17 14:30:00 - __main__ - INFO -   Lease TTL: 1h
2025-10-17 14:30:00 - __main__ - INFO -   Workers: 4
2025-10-17 14:30:00 - __main__ - INFO -   Total leases to generate: 1000

============================================================
LOAD GENERATION SUMMARY
============================================================

Configuration:
  Mode: pki
  Parent namespace: loadtest
  Namespaces: 10
  Workers: 4
  Leases per namespace: 100
  Lease TTL: 1h

Results:
  Namespaces processed: 10
  Namespaces created: 10
  Leases created: 1000
  Leases failed: 0

Performance:
  Duration: 95.23 seconds
  Operations per second: 14.32
  Leases per second: 10.50

============================================================
```

## Troubleshooting
**Vault is sealed:**
```bash
task vault:unseal
```

**Certificate issues:**
```bash
task certs:verify
```

**View logs:**
```bash
task logs
task logs:vault
task logs:haproxy
```
