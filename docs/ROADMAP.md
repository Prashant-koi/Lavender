# Roadmap

## Implemented
- Rust eBPF agent with local detection, scoring, and response flow
- raw telemetry publish over NATS on `telemetry.raw.<tenant>.<agent_id>`
- heartbeat publish over NATS on `heartbeat.<tenant>.<agent_id>`
- Go ingest service that validates transport messages and republishes canonical telemetry on `telemetry.accepted.<tenant>.<agent_id>`
- Go telemetry-writer service that consumes canonical `exec` events
- local Docker stack for `nats`, `ingest`, `telemetry-writer`, and `agent`

## In Progress
- moving more event types from local-only handling into the backend transport path
- reducing how much detection and correlation logic still lives inside the Rust agent
- tightening the contract between transport events and canonical events

## Next
- publish `open` and `connect` activity through the transport layer
- add backend detection workers
- add command/policy subject handling in the agent
- persist canonical telemetry to a real database instead of logging shaped rows
- add control-plane APIs and alert lifecycle management
- add a dashboard
