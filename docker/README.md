# Docker Dev Services

This directory holds the local container workflows for Lavender infrastructure and agent testing.

## Current Pieces
- `nats/compose.yml`: broker-only workflow for local NATS
- `agent/`: Docker build and runtime config for the Rust agent
- `ingest/`: Docker build for the Go ingest service
- `telemetry-writer/`: Docker build for the canonical telemetry consumer
- `compose/README.md`: full stack and test workflows

## Current Full Stack
The root `docker-compose.yml` starts:

- `nats`
- `ingest`
- `telemetry-writer`
- `agent`

Planned infra such as PostgreSQL, TimescaleDB, Redis, and control-plane services are not in the compose stack yet.
