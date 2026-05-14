# Local NATS / JetStream

This directory contains the local development setup for the Lavender broker.

Files:

- `compose.yml`
  - starts a local `NATS / JetStream` broker for telemetry and heartbeat testing

## Start Broker Only

From repository root:

```bash
docker compose -f docker/nats/compose.yml up -d
```

For the full local stack instead, see:

- [../compose/README.md](../compose/README.md)

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
