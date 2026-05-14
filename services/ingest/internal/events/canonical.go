package events

type CanonicalEvent struct {
	SchemaVersion    uint16             `json:"schema_version"`
	AgentID          string             `json:"agent_id"`
	TenantID         *string            `json:"tenant_id"`
	Host             HostInfo           `json:"host"`
	ObservedAtUnixMs int64              `json:"observed_at_unix_ms"`
	ReceivedAtUnixMs int64              `json:"received_at_unix_ms"`
	Event            TransportEventKind `json:"event"`
}
