package detection

import (
	"fmt"

	"github.com/Prashant-koi/lavender/services/platform/events"
	"github.com/google/uuid"
)

func AlertSubject(alert events.AlertEvent) string {
	tenant := "unknown"
	if alert.TenantID != nil && *alert.TenantID != "" {
		tenant = *alert.TenantID
	}

	return fmt.Sprintf("alerts.%s.%s", tenant, alert.AgentID)
}

func newAlert(evt events.CanonicalEvent, rule, severity, detail string) events.AlertEvent {
	return events.AlertEvent{
		SchemaVersion:    1,
		AlertID:          uuid.NewString(),
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
