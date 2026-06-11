# Roadmap

## Implemented
- Rust eBPF agent with local detection, scoring, and response flow
- raw telemetry publish over NATS on `telemetry.raw.<tenant>.<agent_id>`
- heartbeat publish over NATS on `heartbeat.<tenant>.<agent_id>`
- Go ingest service that validates transport messages and republishes canonical telemetry on `telemetry.accepted.<tenant>.<agent_id>`
- Go telemetry-writer service that consumes canonical `exec` events
- local Docker stack for `nats`, `ingest`, `telemetry-writer`, and `agent`
- added backend detection workers
- persist canonical telemetry to timescaledb
- add command/policy subject handling in the agent
- add control-plane APIs and alert lifecycle management

## In Progress
- moving more event types from local-only handling into the backend transport path
- reducing how much detection and correlation logic still lives inside the Rust agent
- presistance engine for the detection workers for pid persistance and alert corelation
- extensive APIs for control-plane
- respone (to the endpoints) in the control-plane

## Next
- add a dashboard
