package events

// i am writing the shared shcema for all go servcies since the codebase is kinda messy right now
// this is athe mirror of Rust transport structs in ./common/src/transport.rs
// like a mirror of one chanes other must

// AgentTelemetryEvent is published on telemetry.raw.<tenant>.<agent_id> and heartbeat.<tenant>.<agent_id>
// its the raw events
type AgentTelemetryEvent struct {
	SchemaVersion    uint16             `json:"schema_version"`
	AgentID          string             `json:"agent_id"`
	TenantID         *string            `json:"tenant_id"`
	Host             HostInfo           `json:"host"`
	ObservedAtUnixMs int64              `json:"observed_at_unix_ms"`
	Event            TransportEventKind `json:"event"`
}

type HostInfo struct {
	Hostname string `json:"hostname"`
}

// this is the representaiton of every event varient the agent can emit
// only Type is non optional
type TransportEventKind struct {
	Type     string   `json:"type"` // can be "exec", "open", "connect", "heartbeat" as of now
	PID      uint32   `json:"pid,omitempty"`
	PPID     uint32   `json:"ppid,omitempty"`
	UID      uint32   `json:"uid,omitempty"`
	Comm     string   `json:"comm,omitempty"`
	Filename string   `json:"filename,omitempty"`
	Argv     []string `json:"argv,omitempty"`
	Status   string   `json:"status,omitempty"`
	DestIP   string   `json:"dest_ip,omitempty"`
	DestPort uint16   `json:"dest_port,omitempty"`
	AF       uint16   `json:"af,omitempty"`
}
