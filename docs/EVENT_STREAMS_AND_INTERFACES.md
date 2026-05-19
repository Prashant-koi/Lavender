# Event Streams And Interfaces

This page documents the implementation-facing names that change more often than the high-level README.

## Current Boundary Split
- kernel to agent: fixed-size Rust structs in `common/src/lib.rs`
- agent to NATS: transport JSON defined in `common/src/transport.rs`
- ingest to backend consumers: canonical JSON defined in `services/ingest/internal/events/canonical.go`

## eBPF Programs And Ring Buffers
`lavender-ebpf/src/main.rs` currently defines four tracepoint programs:

- `handle_execve` attached to `syscalls/sys_enter_execve`
- `handle_exit` attached to `sched/sched_process_exit`
- `handle_open` attached to `syscalls/sys_enter_openat`
- `handle_connect` attached to `syscalls/sys_enter_connect`

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

## NATS Subject Families
The implemented subject layouts are:

- raw telemetry: `telemetry.raw.<tenant>.<agent_id>`
- heartbeats: `heartbeat.<tenant>.<agent_id>`
- canonical telemetry after ingest: `telemetry.accepted.<tenant>.<agent_id>`

The current code publishes raw telemetry from `agent/src/publisher.rs` and derives canonical subjects in `services/ingest/internal/ingest/subject.go`.

## Raw Transport Payload
`common/src/transport.rs` defines the agent-published transport envelope:

- `schema_version`
- `agent_id`
- `tenant_id`
- `host.hostname`
- `observed_at_unix_ms`
- `event`

`event` is a tagged enum with these currently implemented variants:

- `exec`
- `heartbeat`

### `exec` transport fields
- `pid`
- `ppid`
- `uid`
- `comm`
- `filename`
- `argv`

### `heartbeat` transport fields
- `status`

Current heartbeat status emitted by the agent:

- `alive`

## Canonical Payload
The ingest service republishes accepted messages as canonical events with:

- all raw transport fields
- `received_at_unix_ms`

The payload shape is otherwise the same event model today. Ingest validates the raw message, stamps server receive time, then republishes it on `telemetry.accepted.<tenant>.<agent_id>`.

## Current Backend Coverage
There is an important gap between local detection coverage and backend transport coverage:

- local agent processing handles `exec`, `exit`, `open`, and `connect`
- NATS transport currently publishes only `exec` and `heartbeat`
- `services/telemetry-writer` currently only processes canonical `exec` events

So the backend path is real, but it is not yet a full mirror of everything the agent sees locally.
