package events

// CanonicalEvent repubed by inges on telemetry.accepted.<tenant>.<agent_id>
// like it name (canonical) all services like the detection, telemetry-writer and anythign else will consume this
type CanonicalEvent struct {
	SchemaVersion    uint16             `json:"schema_version"`
	EventID          string             `json:"event_id"` // gonna be the uuid
	AgentID          string             `json:"agent_id"`
	TenantID         *string            `json:"tenant_id"`
	Host             HostInfo           `json:"host"`
	ObservedAtUnixMs int64              `json:"observed_at_unix_ms"`
	ReceivedAtUnixMs int64              `json:"received_at_unix_ms"`
	Event            TransportEventKind `json:"event"`
}
