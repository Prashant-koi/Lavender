# Local NATS / JetStream

This directory contains the local development setup for the Lavender broker.

Files:

- `compose.yml`
  - starts a local `NATS / JetStream` broker for telemetry and heartbeat testing

## Start

From repository root:

```bash
docker compose -f docker/nats/compose.yml up -d
```

## Check Telemetry

Subscribe to raw telemetry:

```bash
nats sub "telemetry.raw.>"
```

Subscribe to heartbeats:

```bash
nats sub "heartbeat.>"
```

Current subject conventions:

- `telemetry.raw.<tenant>.<agent_id>`
- `heartbeat.<tenant>.<agent_id>`

## Stop

```bash
docker compose -f docker/nats/compose.yml down
```
