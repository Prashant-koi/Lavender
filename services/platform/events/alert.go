package events

// AlertEvent is publisjed on alerts.<tenant>.<agent_id>
type AlertEvent struct {
	SchemaVersion    uint16  `json:"schema_version"`
	AlertID          string  `json:"alert_id"`
	TenantID         *string `json:"tenant_id"`
	AgentID          string  `json:"agent_id"`
	Hostname         string  `json:"hostname"`
	Rule             string  `json:"rule"`
	Severity         string  `json:"severity"`
	EventType        string  `json:"event_type"`
	PID              uint32  `json:"event_pid,omitempty"`
	Comm             string  `json:"event_comm,omitempty"`
	Detail           string  `json:"detail"`
	CreatedAtUnixMs  int64   `json:"created_at_unix_ms"`
	ObservedAtUnixMs int64   `json:"observed_at_unix_ms"`
	ReceivedAtUnixMs int64   `json:"received_at_unix_ms"`
}
