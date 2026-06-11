package ingest

import (
	"fmt"

	"github.com/Prashant-koi/lavender/services/platform/events"
)

func CanonicalSubject(evt events.AgentTelemetryEvent) string {
	tenant := "unknown"
	if evt.TenantID != nil && *evt.TenantID != "" {
		tenant = *evt.TenantID
	}

	return fmt.Sprintf("telemetry.accepted.%s.%s", tenant, evt.AgentID)
}
