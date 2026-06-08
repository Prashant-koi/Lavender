package events

type AlertEvent struct {
	AlertID          string `json:"alert_id"`
	TenantID         string `json:"tenant_id"`
	AgentID          string `json:"agent_id"`
	Rule             string `json:"rule"`
	Severity         string `json:"severity"`
	Detail           string `json:"detail"`
	EventType        string `json:"event_type"`
	EventPID         uint32 `json:"event_pid"`
	EventComm        string `json:"event_comm"`
	ObservedAtUnixMs int64  `json:"observed_at_unix_ms"`
	ReceivedAtUnixMs int64  `json:"received_at_unix_ms"`
}
