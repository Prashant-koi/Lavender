package detection

import (
	"fmt"

	"github.com/Prashant-koi/lavender/detection/internal/events"
)

type AlertEvent struct {
	SchemaVersion    uint16  `json:"schema_version"`
	TenantID         *string `json:"tenant_id"`
	AgentID          string  `json:"agent_id"`
	Hostname         string  `json:"hostname"`
	Rule             string  `json:"rule"`
	Severity         string  `json:"severity"`
	EventType        string  `json:"event_type"`
	PID              uint32  `json:"pid,omitempty"`
	Comm             string  `json:"comm,omitempty"`
	Detail           string  `json:"detail"`
	CreatedAtUnixMs  int64   `json:"created_at_unix_ms"`
	ObservedAtUnixMs int64   `json:"observed_at_unix_ms"`
	ReceivedAtUnixMs int64   `json:"received_at_unix_ms"`
}

func AlertSubject(alert AlertEvent) string {
	tenant := "unknown"
	if alert.TenantID != nil && *alert.TenantID != "" {
		tenant = *alert.TenantID
	}

	return fmt.Sprintf("alerts.%s.%s", tenant, alert.AgentID)
}

func newAlert(evt events.CanonicalEvent, rule, severity, detail string) AlertEvent {
	return AlertEvent{
		SchemaVersion:    1,
		TenantID:         evt.TenantID,
		AgentID:          evt.AgentID,
		Hostname:         evt.Host.Hostname,
		Rule:             rule,
		Severity:         severity,
		EventType:        evt.Event.Type,
		PID:              evt.Event.PID,
		Comm:             evt.Event.Comm,
		Detail:           detail,
		CreatedAtUnixMs:  evt.ReceivedAtUnixMs,
		ObservedAtUnixMs: evt.ObservedAtUnixMs,
		ReceivedAtUnixMs: evt.ReceivedAtUnixMs,
	}
}
