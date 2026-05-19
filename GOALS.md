# Feature Goals

These are medium-term goals that are not implemented yet:

- publish more than `exec` and `heartbeat` on the backend transport path
- add backend detection workers so the Rust agent can become thinner over time
- persist canonical telemetry to a database instead of only logging shaped rows
- add beaconing-pattern detection
- add TLS fingerprinting such as JA4-style metadata
- expand automated test coverage across the Go services and end-to-end transport path
