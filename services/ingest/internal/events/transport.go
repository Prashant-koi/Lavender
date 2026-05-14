package events

// we will just mirror the structs in the ./common/src/transport.rs here

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

type TransportEventKind struct {
	Type     string   `json:"type"`
	PID      uint32   `json:"pid,omitempty"`
	PPID     uint32   `json:"ppid,omitempty"`
	UID      uint32   `json:"uid,omitempty"`
	Comm     string   `json:"comm,omitempty"`
	Filename string   `json:"filename,omitempty"`
	Argv     []string `json:"argv,omitempty"`
	Status   string   `json:"status,omitempty"`
}
