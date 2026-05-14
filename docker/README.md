# Docker Dev Services

This directory holds local development containers used by Lavender infrastructure.

Current services:

- `nats/compose.yml`
  - local `NATS / JetStream` broker for agent telemetry and heartbeat testing
- `agent/`
  - Docker build and runtime config for the Rust eBPF agent
- `ingest/`
  - Docker build for the Go ingest service
- `compose/README.md`
  - full local stack and test compose workflows

The goal of this directory is to keep root clean from all the cultter that might come in the future, such as:

- PostgreSQL / TimescaleDB
- Redis
- control-plane or ingest dev dependencies
