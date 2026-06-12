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

// making the alertID determinitic this is interesiting
// say a canonical streeam comes setection detects 2 alerts and published to alert #1
// but the 2nd alert fails to publish so we try again before we were doing NewString()
// which is a random function and since we are uisng jetstream now it sees it as new and
// makes it a different alert even tho the alert is for the same thing
// that is why we are hasing the alert ID in the struct return below since it is
// deterministic
var alertIDNamespace = uuid.MustParse("76e29df4-4dcb-4f24-a8e2-0b8a4976e1c4")

func newAlert(evt events.CanonicalEvent, rule, severity, detail string) events.AlertEvent {
	return events.AlertEvent{
		SchemaVersion:    1,
		AlertID:          uuid.NewSHA1(alertIDNamespace, []byte(evt.EventID+"|"+rule)).String(),
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
