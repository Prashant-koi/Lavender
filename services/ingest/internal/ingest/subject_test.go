package ingest

import (
	"testing"

	"github.com/Prashant-koi/lavender/services/platform/events"
)

func TestCanonicalSubject_WithTenant(t *testing.T) {
	tenant := "dev"
	evt := events.AgentTelemetryEvent{
		EventID:  "11111111-2222-3333-4444-555555555555",
		AgentID:  "agent-1",
		TenantID: &tenant,
	}

	got := CanonicalSubject(evt)
	want := "telemetry.accepted.dev.agent-1"

	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestCanonicalSubject_WithoutTenant(t *testing.T) {
	evt := events.AgentTelemetryEvent{
		EventID:  "11111111-2222-3333-4444-555555555555",
		AgentID:  "agent-1",
		TenantID: nil,
	}

	got := CanonicalSubject(evt)
	want := "telemetry.accepted.unknown.agent-1"

	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
