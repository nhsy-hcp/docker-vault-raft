# docker-vault-raft

## Overview

This repository provides a Docker Compose stack for running a Vault Enterprise cluster with integrated raft storage and HAProxy load balancer.

## Prerequisites

- [Docker](https://www.docker.com/get-started)
- [go-task](https://taskfile.dev) and [jq](https://stedolan.github.io/jq/) (for automation scripts)

Note: `/vault/logs` is mounted as a tmpfs with a maximum size of 100MB.

Install prerequisites on macOS:
```sh
brew install go-task jq
```

## Setup
Setup
Clone the repository:
```sh
git clone https://github.com/nhsy-hcp/docker-vault-raft.git
cd docker-vault-raft
```
Create a .env file in the root directory:
```sh
cp .env.example .env
# Edit .env to add your Vault license
```
Start the stack:
```sh
task up
```
Initialize and unseal Vault:
```sh
task init
task unseal
task logs
```
Vault token is automatically added to the .env file with `task init`. Load the environment variables:
```sh
source .env
vault token lookup
```

Accessing Services
- Vault 1 UI: http://localhost:8201
- Vault 2 UI: http://localhost:8202
- Vault 3 UI: http://localhost:8200
- HAProxy LB: http://localhost:8200
- HAProxy Stats: http://localhost:8080/stats

## Common Tasks
Start stack: `task up`

Stop stack: `task stop`

View logs: `task logs`

View raft status: `task raft`

Run benchmark: `task benchmark`

Check Vault status: `task status`

Delete cluster: `task clean` or `task rm`

Open UI in browser: `task ui`
