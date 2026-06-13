# Roadmap

## Implemented
- Rust eBPF agent with local detection, scoring, and response flow
- agent publishes `exec`, `open`, `connect`, and `exit` telemetry plus `heartbeat`
  over NATS, with an agent-generated `event_id` on every event
- telemetry rides JetStream end to end: agent publishes with persistence acks,
  streams `TELEMETRY_RAW`, `TELEMETRY_CANONICAL`, and `ALERTS`, durable consumers
  with explicit acks, and message-id dedup
- Go ingest service: validates raw transport, stamps server receive time, and
  republishes canonical telemetry on `telemetry.accepted.<tenant>.<agent_id>`
- Go telemetry-writer service: persists `exec`, `open`, and `connect` rows to
  TimescaleDB hypertables
- Go detection service: rule evaluation (suspicious port, shell outbound
  connection, unexpected shell spawn, sensitive file read) and correlation
  (credential access then execution), with per-`(tenant, agent, pid)` state and
  exit-driven eviction; emits alerts with a deterministic `alert_id`
- Go alert-writer service: persists alerts, idempotent via a unique `alert_id`
  index plus `ON CONFLICT DO NOTHING`
- Go control-plane service: HTTP API to list alerts and update alert lifecycle
  status, backed by Postgres
- shared `services/platform` module: NATS/JetStream helpers, Postgres, env,
  shutdown, and the single Go copy of the event schema
- local Docker stack (`nats`, `timescaledb`, `ingest`, `telemetry-writer`,
  `detection`, `alert-writer`, `control-plane`, `agent`) with host ports bound to
  localhost only, a Postgres healthcheck, and dependency gating

## In Progress / Next
- edge security: NATS per-agent auth, TLS, and an ingest subject↔payload check
  (must land before the command/response path)
- command/policy/response path from control-plane back to the agent over
  `cmd.<tenant>.<agent_id>`
- heartbeat consumption and host liveness / fleet health tracking
- reducing detection and correlation that still runs inside the Rust agent
- externalized correlation state for stateless, horizontally-scaled detection
- agent observability: ring-buffer drop counters and publish-failure counters
- service metrics and health endpoints
- TimescaleDB retention and compression policies
- a dashboard
