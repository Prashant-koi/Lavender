# Docker Compose Workflows

## Main Stack

Run the local broker, ingest service, and eBPF agent:

```bash
DOCKER_BUILDKIT=1 docker compose up --build
```

This starts:

- `nats`
- `ingest`
- `agent`

If you want to stop and restart cleanly:

```bash
docker compose down
DOCKER_BUILDKIT=1 docker compose up --build
```

## Logs

Watch the service logs in another terminal:

```bash
docker compose logs -f nats ingest agent
```

What you want to see:

- `nats`
  - `Server is ready`
- `ingest`
  - `ingest service listening on telemetry.raw.>`
- `agent`
  - `Lavender is watching. Ctrl+C to stop`

When raw telemetry is flowing through ingest, you should also see lines like:

```text
accepted and republished telemetry.raw.dev.docker-agent-1 => telemetry.accepted.dev.docker-agent-1
```

## NATS Subscriptions

Subscribe to the broker from the host to verify each subject family.

Heartbeats:

```bash
nats sub "heartbeat.>"
```

Raw agent telemetry:

```bash
nats sub "telemetry.raw.>"
```

Canonical telemetry republished by ingest:

```bash
nats sub "telemetry.accepted.>"
```

## Triggering Telemetry

After subscribing to `telemetry.raw.>` and `telemetry.accepted.>`, trigger fresh exec activity:

```bash
docker exec lavender-agent /bin/sh -lc 'echo hello && ls /tmp && uname -a'
```

That should produce:

- a raw event on `telemetry.raw.<tenant>.<agent_id>`
- a canonical event on `telemetry.accepted.<tenant>.<agent_id>`

## Container Visibility

The Compose stack currently runs the agent inside the `lavender-agent` container.

That means:

- the agent mainly observes the container environment
- you will not see the full background activity of your host laptop
- telemetry volume will be much lower than when running the agent directly on the host

If you want more realistic host telemetry:

- keep `nats` and `ingest` in Docker
- run the Rust agent on the host
- point it at `nats://127.0.0.1:4222`

## Tests

Run the current automated test containers:

```bash
docker compose -f docker-compose.test.yaml up --build --abort-on-container-exit
```

Current test services:

- `agent-tests`
  - runs `cargo test -p agent --tests`
- `ingest-tests`
  - runs `go test ./...` inside `services/ingest`
