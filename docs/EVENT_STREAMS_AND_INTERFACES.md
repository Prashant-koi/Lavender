# Event Streams And Interfaces

This page documents the implementation-facing names that change more often than the high-level README.

## Current Boundary Split
- kernel to agent: fixed-size Rust structs in `common/src/lib.rs`
- agent to NATS: transport JSON defined in `common/src/transport.rs`
- agent to backend, and backend to backend: shared Go schema in `services/platform/events`
  (`transport.go`, `canonical.go`, `alert.go`) — the Go mirror of the Rust transport structs

## eBPF Programs And Ring Buffers
`lavender-ebpf/src/main.rs` currently defines four tracepoint programs:

- `handle_execve` attached to `syscalls/sys_enter_execve`
- `handle_exit` attached to `sched/sched_process_exit`
- `handle_open` attached to `syscalls/sys_enter_openat`
- `handle_connect` attached to `syscalls/sys_enter_connect`

`handle_exit` only emits when `tid == tgid` (real process death), so a thread exit
inside a live multithreaded process does not produce an exit event.

The userspace bootstrap opens four ring buffer maps with these exact names:

- `EXEC_EVENTS`
- `EXIT_EVENTS`
- `OPEN_EVENTS`
- `CONN_EVENTS`

Each map carries the following struct:

- `EXEC_EVENTS`: `ExecEvent { pid, ppid, uid, comm, filename, argv1, argv2 }`
- `EXIT_EVENTS`: `ExitEvent { pid }`
- `OPEN_EVENTS`: `OpenEvent { pid, comm, filename }`
- `CONN_EVENTS`: `ConnEvent { pid, uid, comm, daddr, dport, af }`

## Local Agent Output Interface
The Rust agent still emits local JSON to the terminal even when NATS transport is enabled.

Stdout event `type` values:

- `exec`
- `conn`

Stderr event `type` values:

- `alert`

Stderr response `kind` value:

- `response`

Current scored alerts may include these optional fields:

- `base_score`
- `lineage_bonus`
- `rarity_bonus`
- `sequence_bonus`

## NATS Subjects And JetStream Streams
Subject layouts:

- raw telemetry: `telemetry.raw.<tenant>.<agent_id>`
- canonical telemetry after ingest: `telemetry.accepted.<tenant>.<agent_id>`
- alerts: `alerts.<tenant>.<agent_id>`
- heartbeats: `heartbeat.<tenant>.<agent_id>`

Telemetry and alerts ride on JetStream (file storage, defined in
`services/platform/natsx/jetstream.go`):

- `TELEMETRY_RAW` captures `telemetry.raw.>`
- `TELEMETRY_CANONICAL` captures `telemetry.accepted.>`
- `ALERTS` captures `alerts.>`

Each backend service binds a named durable consumer with explicit acks
(`ingest`, `detection`, `telemetry-writer`, `alert-writer`). Reusing a durable
name across instances load-balances work, so services scale horizontally.

Heartbeats stay on core NATS, not JetStream — a stale liveness signal has no
value, so there is nothing to persist or replay. Nothing consumes heartbeats yet.

## Raw Transport Payload
`common/src/transport.rs` defines the agent-published transport envelope:

- `schema_version`
- `event_id` — agent-generated UUID, used as the JetStream dedup message id
- `agent_id`
- `tenant_id`
- `host.hostname`
- `observed_at_unix_ms`
- `event`

`event` is a tagged enum (`type` selects the variant) with these implemented variants:

- `exec`: `pid`, `ppid`, `uid`, `comm`, `filename`, `argv`
- `open`: `pid`, `comm`, `filename`
- `connect`: `pid`, `uid`, `comm`, `dest_ip`, `dest_port`, `af`
- `exit`: `pid`
- `heartbeat`: `status` (currently always `alive`)

## Canonical Payload
Ingest validates the raw message, stamps server receive time, and republishes
on `telemetry.accepted.<tenant>.<agent_id>`. The canonical event is the raw
envelope plus `received_at_unix_ms`. The `event_id` is carried through unchanged
and reused as the dedup message id on republish.

## Alert Payload
Detection publishes `events.AlertEvent` on `alerts.<tenant>.<agent_id>`:

- `schema_version`, `alert_id`, `tenant_id`, `agent_id`, `hostname`
- `rule`, `severity`, `detail`, `event_type`
- `event_pid`, `event_comm`
- `created_at_unix_ms`, `observed_at_unix_ms`, `received_at_unix_ms`

`alert_id` is a deterministic UUIDv5 over `(event_id, rule)`, so the same event
tripping the same rule always yields the same id.

## Delivery And Dedup
The pipeline is at-least-once, so duplicates are possible and handled in two layers:

- **Layer 1 — JetStream message-id dedup.** Every publish carries a message id
  (`event_id` for telemetry, `alert_id` for alerts) and streams drop repeats
  within a 2-minute window. This keeps streams clean against duplicate *publishes*
  (producer retries, or a consumer reprocessing then re-publishing after a crash).
- **Layer 2 — database uniqueness.** A redelivered message handed to a consumer
  that writes directly to Postgres is not a publish, so Layer 1 does not cover it.
  The `alerts` table has a unique index on `alert_id` with `ON CONFLICT DO NOTHING`
  to make alert inserts idempotent.

Telemetry tables (`exec_events`, `open_events`, `connect_events`) intentionally
do **not** enforce `event_id` uniqueness: they are high-write hypertables, a
duplicate telemetry row is harmless analytical noise (it cannot cause a false
alert, since detection runs off the stream), and read-time `GROUP BY event_id`
is the fallback if exact counts ever matter.

## Current Backend Coverage
- the agent publishes `exec`, `open`, `connect`, `exit`, and `heartbeat`
- `services/telemetry-writer` persists `exec`, `open`, and `connect` rows
  (`exit` and `heartbeat` are acknowledged and skipped)
- `services/detection` evaluates rules and correlation and emits alerts
- `services/alert-writer` persists alerts
- `services/control-plane` exposes the alert list/lifecycle HTTP API

Not yet wired: command/policy/response subjects back to the agent, heartbeat
consumption / host liveness, and edge authentication (NATS auth + TLS).
