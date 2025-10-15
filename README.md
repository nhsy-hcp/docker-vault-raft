# Docker Vault Raft Cluster with TLS

A production-ready HashiCorp Vault Enterprise cluster with end-to-end TLS encryption, Raft consensus storage, and HAProxy load balancing.

## Features

- **3-node Vault cluster** with automatic leader election
- **End-to-end TLS encryption** using self-signed certificates
- **HAProxy load balancer** with TLS passthrough
- **Raft consensus storage** for high availability
- **Automated certificate management**
- **Health-aware load balancing**

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

### 2. Generate TLS Certificates

```bash
# Generate all certificates (CA + server certs)
task certs:all
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

All connections use HTTPS with TLS:

- **Vault Node 1**: https://localhost:8201
- **Vault Node 2**: https://localhost:8202
- **Vault Node 3**: https://localhost:8203
- **HAProxy**: https://localhost:8200
- **HAProxy Stats**: http://localhost:8080/stats (admin/changeme)

## Common Commands

**Certificate Management:**
```bash
task certs:all      # Generate all certificates
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
task health         # Health check
task metrics        # Prometheus metrics
```

**Testing:**
```bash
task test:tls       # Test TLS connections
task test:cluster   # Test cluster formation
task test:failover  # Test HA failover
```

## Security Notes

- Certificate files and unseal keys are automatically excluded from git
- Root CA is valid for 10 years
- Server certificates are valid for 1 year
- Private keys have 600 permissions
- TLS 1.2+ with strong cipher suites

## Architecture

```
Client → HAProxy:8200 (TLS Passthrough) →
    ├─ vault-1:8201 (Raft Node, TLS)
    ├─ vault-2:8202 (Raft Node, TLS)
    └─ vault-3:8203 (Raft Node, TLS)
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
```

For detailed documentation, see `CLAUDE.md`.
