# Local NATS

This directory contains the broker-only development setup for Lavender.

## Start Broker Only
From the repository root:

```bash
docker compose -f docker/nats/compose.yml up -d
```

For the full local stack instead, see [../compose/README.md](../compose/README.md).

## Check Subjects
Subscribe to raw telemetry:

```bash
nats sub "telemetry.raw.>"
```

Subscribe to heartbeats:

```bash
nats sub "heartbeat.>"
```

Subscribe to canonical telemetry republished by ingest:

```bash
nats sub "telemetry.accepted.>"
```

## Current Subject Conventions
- `telemetry.raw.<tenant>.<agent_id>`
- `heartbeat.<tenant>.<agent_id>`
- `telemetry.accepted.<tenant>.<agent_id>`

## Stop

```bash
docker compose -f docker/nats/compose.yml down
```
