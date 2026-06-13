# Docker Compose Workflows

## Main Stack

Run the local broker, database, backend services, and eBPF agent:

```bash
DOCKER_BUILDKIT=1 docker compose up --build
```

This starts:

- `nats`
- `timescaledb`
- `ingest`
- `telemetry-writer`
- `detection`
- `alert-writer`
- `control-plane`
- `agent`

Host ports are bound to `127.0.0.1` only. `timescaledb` has a healthcheck and the
Postgres-dependent services wait for it, so they no longer crash-loop on first boot.

To stop and restart cleanly:

```bash
docker compose down
DOCKER_BUILDKIT=1 docker compose up --build
```

## Logs

Watch the service logs in another terminal:

```bash
docker compose logs -f nats ingest telemetry-writer detection alert-writer control-plane agent
```

Healthy startup signals:

- `nats`: `Server is ready`
- `ingest`: `ingest service consuming durable 'ingest' on stream TELEMETRY_RAW`
- `telemetry-writer`: `telemetry writer consuming durable 'telemetry-writer' on stream TELEMETRY_CANONICAL`
- `detection`: `detection service consuming durable 'detection' on stream TELEMETRY_CANONICAL`
- `alert-writer`: `alert-writer consuming durable 'alert-writer' on stream ALERTS`
- `control-plane`: `control-plane listening on :8080`
- `agent`: `Lavender is watching. Ctrl+C to stop`

When raw telemetry flows through ingest, you should also see a republish log like:

```text
accepeted and republished telemetry.raw.dev.docker-agent-1 => telemetry.accepted.dev.docker-agent-1
```

## NATS Subscriptions

Subscribe from the host to inspect each subject family:

```bash
nats sub "heartbeat.>"
nats sub "telemetry.raw.>"
nats sub "telemetry.accepted.>"
nats sub "alerts.>"
```

Inspect the JetStream streams and consumers directly:

```bash
nats stream ls
nats consumer report TELEMETRY_CANONICAL
```

## Triggering Telemetry

After subscribing to `telemetry.raw.>` and `telemetry.accepted.>`, trigger fresh exec activity:

```bash
docker exec lavender-agent /bin/sh -lc 'echo hello && ls /tmp && uname -a'
```

That should produce:

- a raw event on `telemetry.raw.<tenant>.<agent_id>`
- a canonical event on `telemetry.accepted.<tenant>.<agent_id>`

The agent publishes `exec`, `open`, `connect`, and `exit` telemetry plus `heartbeat`.
Detected activity (for example a connection to a suspicious port) produces an alert
on `alerts.<tenant>.<agent_id>`, which `alert-writer` persists to Postgres.

## Container Visibility

The compose stack runs the agent inside the `lavender-agent` container.

That means:

- the agent mainly observes the container environment
- you will not see the full background activity of your host
- telemetry volume is lower than when running the agent directly on the host

For more realistic host telemetry:

- keep `nats`, `ingest`, and optionally `telemetry-writer` in Docker
- run the Rust agent on the host
- point it at `nats://127.0.0.1:4222`

## Tests

Run the current automated test containers:

```bash
docker compose -f docker-compose.test.yaml up --build --abort-on-container-exit
```

Current test services:

- `agent-tests`: runs `cargo test -p agent --tests`
- `ingest-tests`: runs `go test ./...` inside `services/ingest`

`services/telemetry-writer` has Go tests in the repo, but they are not yet wired into `docker-compose.test.yaml`.
